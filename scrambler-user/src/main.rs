use anyhow::Context;
use aya::{
    include_bytes_aligned,
    programs::{ SchedClassifier, TcAttachType},
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use tokio::signal;

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
        "../../target/bpfel-unknown-none/release/libscrambler_ebpf.so"
    ))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let program: &mut SchedClassifier = bpf
        .program_mut("scrambler")
        .context("program 'scrambler' not found")?
        .try_into()?;

    program.load()?;
    program.attach(&opt.iface, TcAttachType::Egress)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
