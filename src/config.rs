use std::net::IpAddr;

use clap::Parser;

#[derive(Debug, Parser, Clone)]
#[command(
    name = "Chronos-Track",
    about = "Quartz clock skew tracker via passive TCP timestamps"
)]
pub struct Config {
    #[arg(long = "interface")]
    pub interface: String,

    #[arg(long = "target-ip")]
    pub target_ip: Option<IpAddr>,

    #[arg(long = "target-port", default_value_t = 80)]
    pub target_port: u16,
}

impl Config {
    pub fn from_args() -> Self {
        Self::parse()
    }
}
