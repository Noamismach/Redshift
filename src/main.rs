mod analysis;
mod config;
#[cfg(target_os = "linux")]
mod injector;
#[cfg(not(target_os = "linux"))]
mod injector {
    use std::io;
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    pub fn suppress_rst(_: u16) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "RST suppression requires Linux iptables",
        ))
    }

    pub fn cleanup_rst(_: u16) {}

    pub fn start_injection_loop(_: Ipv4Addr, _: u16, _: u16, _: Arc<AtomicU64>) {}
}
#[cfg(target_os = "linux")]
mod sniffer;
#[cfg(not(target_os = "linux"))]
mod sniffer {
    use std::io;

    use socket2::Socket;

    #[derive(Debug, Clone)]
    pub struct PacketSample {
        pub kernel_time_ns: u64,
        pub sender_ts_val: u32,
        pub src_ip: std::net::IpAddr,
    }

    pub fn create_precision_socket(_: &str) -> io::Result<Socket> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sniffer requires Linux SO_TIMESTAMPING",
        ))
    }

    pub fn recv_packet(_: &Socket) -> io::Result<Option<PacketSample>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sniffer requires Linux SO_TIMESTAMPING",
        ))
    }
}
mod ui;

use std::error::Error;
use std::fs::File;
use std::io::{self, BufWriter};
use std::process;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use analysis::{calculate_skew, interpret_report, Interpretation, Observation, SkewReport};
use config::Config;
use socket2::Socket;
use std::net::{IpAddr, Ipv4Addr};
use ui::UiState;

const ANALYSIS_INTERVAL: u64 = 50;
const NS_PER_SEC: f64 = 1_000_000_000.0;
const SOURCE_PORT: u16 = 54_321;
const UI_TICK_RATE: Duration = Duration::from_millis(50);

#[derive(Debug, Clone)]
struct Measurement {
    kernel_time_ns: u64,
    sender_ts_val: u32,
    src_ip: IpAddr,
}

fn main() {
    env_logger::init();

    if let Err(err) = run() {
        log::error!("Chronos-Track terminated: {err}");
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let cfg = Config::from_args();
    let target_filter = cfg.target_ip;
    let injection_target = resolve_target_v4(target_filter)?;
    let target_port = cfg.target_port;
    let observations: Arc<Mutex<Vec<Observation>>> = Arc::new(Mutex::new(Vec::new()));
    let latest_report: Arc<Mutex<Option<SkewReport>>> = Arc::new(Mutex::new(None));
    let latest_interpretation: Arc<Mutex<Option<Interpretation>>> = Arc::new(Mutex::new(None));
    let status_text = Arc::new(Mutex::new(String::from("Waiting for packets...")));
    let adaptive_interval = Arc::new(AtomicU64::new(200));
    let running = Arc::new(AtomicBool::new(true));
    let start_time = Instant::now();

    log::info!(
        "Chronos-Track starting on interface {} (target={:?})",
        cfg.interface,
        target_filter
    );

    let _rst_guard = RstGuard::install(SOURCE_PORT)?;

    ctrlc::set_handler({
        let running = Arc::clone(&running);
        move || {
            running.store(false, Ordering::Relaxed);
        }
    })?;

    let injector_interval = Arc::clone(&adaptive_interval);
    thread::spawn(move || {
        injector::start_injection_loop(
            injection_target,
            target_port,
            SOURCE_PORT,
            injector_interval,
        );
    });

    let socket = match sniffer::create_precision_socket(&cfg.interface) {
        Ok(sock) => sock,
        Err(err) => {
            if err.kind() == io::ErrorKind::PermissionDenied {
                log::error!(
                    "Permission denied opening raw socket on '{}'. Run as root or grant CAP_NET_RAW.",
                    cfg.interface
                );
            }
            return Err(Box::new(err));
        }
    };

    let file = File::create("measurements.csv")?;
    let mut csv_writer = csv::Writer::from_writer(BufWriter::new(file));
    csv_writer.write_record(["kernel_time_ns", "sender_ts_val", "src_ip"])?;
    csv_writer.flush()?;

    let (tx, rx) = mpsc::channel();
    let capture_handle = spawn_capture_thread(
        socket,
        target_filter,
        Arc::clone(&running),
        tx,
    );

    let ui_state = UiState {
        target_ip: target_filter.map(|ip| ip.to_string()),
        target_port,
        start_time,
        status: Arc::clone(&status_text),
        observations: Arc::clone(&observations),
        latest_report: Arc::clone(&latest_report),
        latest_interpretation: Arc::clone(&latest_interpretation),
        running: Arc::clone(&running),
    };

    let mut packet_counter: u64 = 0;
    let ui_result = ui::run_with_handler(ui_state, UI_TICK_RATE, || {
        drain_measurements(
            &rx,
            target_filter,
            &observations,
            &latest_report,
            &latest_interpretation,
            &status_text,
            &adaptive_interval,
            &mut csv_writer,
            &mut packet_counter,
            &running,
        )
    });
    
    running.store(false, Ordering::Relaxed);
    if let Ok(mut status) = status_text.lock() {
        *status = String::from("Stopped (awaiting shutdown)");
    }
    if let Err(err) = capture_handle.join() {
        log::error!("Capture thread panicked: {:?}", err);
    }

    if let Err(err) = csv_writer.flush() {
        log::warn!("Failed to flush CSV writer: {err}");
    }

    let samples = {
        let obs_buf = observations.lock().expect("observation buffer poisoned");
        if let Some(report) = calculate_skew(&obs_buf) {
            print_exit_report(report, obs_buf.len());
        } else {
            println!(
                "Chronos-Track summary: insufficient observations ({} samples).",
                obs_buf.len()
            );
        }
        obs_buf.len()
    };

    if samples == 0 {
        log::warn!("No samples collected during session.");
    }

    ui_result.map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

    Ok(())
}

fn resolve_target_v4(target: Option<IpAddr>) -> Result<Ipv4Addr, Box<dyn Error>> {
    match target {
        Some(IpAddr::V4(ip)) => Ok(ip),
        Some(IpAddr::V6(_)) => Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv6 targets are not supported for active injection",
        ))),
        None => Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--target-ip is required when active injection is enabled",
        ))),
    }
}

struct RstGuard {
    port: u16,
    installed: bool,
}

impl RstGuard {
    fn install(port: u16) -> io::Result<Self> {
        // We want the kernel to stay out of the crafted flow.
        injector::suppress_rst(port)?;
        Ok(Self {
            port,
            installed: true,
        })
    }
}

impl Drop for RstGuard {
    fn drop(&mut self) {
        if self.installed {
            injector::cleanup_rst(self.port);
        }
    }
}

fn print_exit_report(report: SkewReport, samples: usize) {
    let interpretation = interpret_report(&report);
    println!("\n=== Chronos-Track Exit Report ===");
    println!("Samples captured: {}", samples);
    println!("Slope: {:.9}", report.slope);
    println!("Clock Skew: {:.3} ppm", report.ppm);
    println!("R²: {:.4}", report.r_squared);
    println!("Classification: {}", report.verdict);
    println!("=================================");
    println!("--- 🧠 CHRONOS INTELLIGENCE ---");
    println!("Signal Quality: {}", interpretation.stability_desc);
    println!("Hardware Est.:  {}", interpretation.hardware_quality);
    println!("FINAL VERDICT:  {}", interpretation.human_verdict);
    println!("--------------------------------\n");
}

fn spawn_capture_thread(
    socket: Socket,
    target_filter: Option<IpAddr>,
    running: Arc<AtomicBool>,
    sender: mpsc::Sender<Measurement>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        if let Err(err) = sniff_loop(socket, target_filter, running, sender) {
            log::error!("Capture loop terminated: {err}");
        }
    })
}

fn sniff_loop(
    socket: Socket,
    target_filter: Option<IpAddr>,
    running: Arc<AtomicBool>,
    sender: mpsc::Sender<Measurement>,
) -> Result<(), Box<dyn Error>> {
    while running.load(Ordering::Relaxed) {
        let sample = match sniffer::recv_packet(&socket) {
            Ok(Some(sample)) => sample,
            Ok(None) => continue,
            Err(err) => {
                if err.kind() == io::ErrorKind::WouldBlock {
                    continue;
                }
                log::warn!("recv_packet failed: {err}");
                continue;
            }
        };

        if let Some(filter_ip) = target_filter {
            if sample.src_ip != filter_ip {
                continue;
            }
        }

        let measurement = Measurement {
            kernel_time_ns: sample.kernel_time_ns,
            sender_ts_val: sample.sender_ts_val,
            src_ip: sample.src_ip,
        };

        if sender.send(measurement).is_err() {
            break;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn drain_measurements(
    receiver: &Receiver<Measurement>,
    target_filter: Option<IpAddr>,
    observations: &Arc<Mutex<Vec<Observation>>>,
    latest_report: &Arc<Mutex<Option<SkewReport>>>,
    latest_interpretation: &Arc<Mutex<Option<Interpretation>>>,
    status_text: &Arc<Mutex<String>>,
    adaptive_interval: &Arc<AtomicU64>,
    csv_writer: &mut csv::Writer<BufWriter<File>>,
    packet_counter: &mut u64,
    running: &Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        let measurement = match receiver.try_recv() {
            Ok(sample) => sample,
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => {
                running.store(false, Ordering::Relaxed);
                break;
            }
        };

        *packet_counter += 1;
        let observation = Observation::new(
            measurement.kernel_time_ns as f64 / NS_PER_SEC,
            measurement.sender_ts_val as f64,
        );

        let mut obs_snapshot: Option<Vec<Observation>> = None;
        {
            let mut guard = observations.lock().expect("observation buffer poisoned");
            guard.push(observation);
            if *packet_counter % ANALYSIS_INTERVAL == 0 {
                obs_snapshot = Some(guard.clone());
            }
        }

        csv_writer.write_record([
            measurement.kernel_time_ns.to_string(),
            measurement.sender_ts_val.to_string(),
            measurement.src_ip.to_string(),
        ])?;
        csv_writer.flush()?;

        if let Ok(mut status) = status_text.lock() {
            *status = format!(
                "Capturing | samples={} | last src={}",
                *packet_counter, measurement.src_ip
            );
        }

        if let Some(obs_snapshot) = obs_snapshot {
            if let Some(report) = calculate_skew(&obs_snapshot) {
                let display_ip = target_filter.unwrap_or(measurement.src_ip);
                let packet_index = *packet_counter;
                log::info!(
                    "[Packet #{packet_index}] Target: {display_ip} | Points: {} | Slope: {:.9} | Skew: {:.2} ppm | R²: {:.3} | Verdict: {}",
                    obs_snapshot.len(),
                    report.slope,
                    report.ppm,
                    report.r_squared,
                    report.verdict
                );

                let interpretation = interpret_report(&report);
                if let Ok(mut guard) = latest_report.lock() {
                    *guard = Some(report.clone());
                }
                if let Ok(mut guard) = latest_interpretation.lock() {
                    *guard = Some(interpretation);
                }

                let new_interval = if report.r_squared > 0.9999 {
                    10
                } else if report.r_squared > 0.99 {
                    100
                } else {
                    500
                };
                adaptive_interval.store(new_interval, Ordering::Relaxed);
            } else {
                log::warn!("Insufficient hull points to compute skew at packet #{packet_counter}");
            }
        }
    }

    Ok(())
}
