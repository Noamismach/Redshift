use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::Write,
    net::Ipv4Addr,
    time::SystemTime,
    time::{Duration, Instant},
};

use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::PerfEventArray,
    programs::{tc, SchedClassifier, TcAttachType},
    util::online_cpus,
    Ebpf,
};
use aya_log::EbpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::{error, info, warn};
use tokio::{io::unix::AsyncFd, signal, sync::mpsc};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/libwatchtower_ebpf.so"
    ))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut SchedClassifier = bpf
        .program_mut("watchtower")
        .context("program 'watchtower' not found")?
        .try_into()?;
    program.load()?;

    if let Err(err) = tc::qdisc_add_clsact(&opt.iface) {
        warn!("failed to add clsact qdisc (continuing): {err}");
    }

    info!("Attempting to attach TC program to {} (ingress)", opt.iface);
    program
        .attach(&opt.iface, TcAttachType::Ingress)
        .context("failed to attach TC program")?;
    info!("Success! TC program attached.");

    let map = bpf.take_map("EVENTS").context("map EVENTS not found")?;
    let mut perf_array = PerfEventArray::try_from(map)?;

    let (tx, mut rx) = mpsc::channel::<u32>(1024);
    let cpus = online_cpus().map_err(|(_, error)| error)?;

    // Bridge kernel perf events into a single async channel for correlation and logging.
    for cpu_id in cpus {
        let buf = perf_array.open(cpu_id, None)?;
        let mut async_buf = AsyncFd::with_interest(buf, tokio::io::Interest::READABLE)?;
        let tx = tx.clone();

        tokio::spawn(async move {
            let mut out_bufs = [BytesMut::with_capacity(1024)];
            loop {
                let mut guard = match async_buf.readable_mut().await {
                    Ok(guard) => guard,
                    Err(_) => break,
                };

                let events = match guard.get_inner_mut().read_events(&mut out_bufs) {
                    Ok(events) => events,
                    Err(_) => {
                        guard.clear_ready();
                        continue;
                    }
                };
                guard.clear_ready();

                for i in 0..events.read {
                    let buf = &out_bufs[i];
                    if buf.len() < 4 {
                        continue;
                    }
                    let mut raw = [0u8; 4];
                    raw.copy_from_slice(&buf[..4]);
                    let ip_raw = u32::from_ne_bytes(raw);
                    let _ = tx.send(ip_raw).await;
                }

                out_bufs[0].clear();

                if events.lost > 0 {
                    warn!("lost {} perf events on CPU {}", events.lost, cpu_id);
                }
            }
        });
    }
    drop(tx);

    info!("Watchtower Active on {}. Press Ctrl-C to stop.", opt.iface);

    // Per-source rate window for scan detection without storing full flow state.
    let mut ip_tracker: HashMap<u32, (Instant, usize)> = HashMap::new();
    let window = Duration::from_secs(1);

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Exiting...");
                break;
            }
            ip_raw = rx.recv() => {
                let Some(ip_raw) = ip_raw else { break; };
                let now = Instant::now();
                let entry = ip_tracker.entry(ip_raw).or_insert((now, 0));

                if now.duration_since(entry.0) > window {
                    *entry = (now, 0);
                }

                entry.1 += 1;
                if entry.1 >= 1 {
                    let ip_str = Ipv4Addr::from(u32::from_be(ip_raw));
                    error!("\n\n [!!!] ⚠️  SCAN DETECTED FROM IP: {} [!!!]\n", ip_str);
                    let packets_detected = entry.1;
                    if let Err(err) = append_alert(ip_str, packets_detected) {
                        warn!("failed to write alert log: {err}");
                    }
                    *entry = (now, 0);
                }
            }
        }
    }

    Ok(())
}

fn append_alert(ip: Ipv4Addr, packets_detected: usize) -> Result<(), std::io::Error> {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("aion_alerts.log")?;
    writeln!(
        file,
        "{{\"timestamp\":{},\"source_ip\":\"{}\",\"event_type\":\"TCP_CLOCK_SKEW_SCAN\",\"packets_detected\":{}}}",
        timestamp,
        ip,
        packets_detected
    )
}
