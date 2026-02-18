use log::{error, info};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Flags, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpOptionNumbers};
use pnet::packet::MutablePacket;
use pnet::transport::{self, TransportChannelType};
use rand::Rng;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Keep kernel from auto-killing the probe flow with RSTs.
pub fn suppress_rst(port: u16) -> std::io::Result<()> {
    // TODO: Audit nftables path; iptables is legacy on some distros.
    let status = Command::new("iptables")
        .args(&[
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "--tcp-flags",
            "RST",
            "RST",
            "--sport",
            &port.to_string(),
            "-j",
            "DROP",
        ])
        .status()?;

    if !status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to add iptables rule for RST suppression",
        ));
    }
    info!(
        "Firewall rule added: Dropping RST packets from port {}",
        port
    );
    Ok(())
}

pub fn cleanup_rst(port: u16) {
    let _ = Command::new("iptables")
        .args(&[
            "-D",
            "OUTPUT",
            "-p",
            "tcp",
            "--tcp-flags",
            "RST",
            "RST",
            "--sport",
            &port.to_string(),
            "-j",
            "DROP",
        ])
        .status();
    info!("Firewall rule removed for port {}", port);
}

// Needs pseudo-header checksum or the peer never sees the SYN.
fn calculate_tcp_checksum(
    tcp_packet: &MutableTcpPacket,
    source_ip: &Ipv4Addr,
    dest_ip: &Ipv4Addr,
) -> u16 {
    pnet::packet::tcp::ipv4_checksum(&tcp_packet.to_immutable(), source_ip, dest_ip)
}

pub fn start_injection_loop(
    target_ip: Ipv4Addr,
    target_port: u16,
    src_port: u16,
    interval_ms: Arc<AtomicU64>,
) {
    let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
    let (mut tx, _) = transport::transport_channel(4096, protocol)
        .expect("raw transport channel failed (need CAP_NET_RAW or root)");

    const TOTAL_LEN: usize = 20 + 20 + 12;
    let mut probe_buf = vec![0u8; TOTAL_LEN];

    loop {
        // Dev Note: route flaps during long runs make this drift; refresh every probe for now.
        let source_ip = find_local_ip(target_ip).unwrap_or(Ipv4Addr::new(0, 0, 0, 0));

        let mut ipv4_packet =
            MutableIpv4Packet::new(&mut probe_buf).expect("probe buffer too small for IPv4 header");
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length(TOTAL_LEN as u16);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ipv4_packet.set_source(source_ip);
        ipv4_packet.set_destination(target_ip);
        ipv4_packet.set_flags(Ipv4Flags::DontFragment);

        let ip_csum = ipv4::checksum(&ipv4_packet.to_immutable());
        ipv4_packet.set_checksum(ip_csum);

        let mut tcp_packet = MutableTcpPacket::new(ipv4_packet.payload_mut())
            .expect("probe buffer too small for TCP header");
        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(target_port);
        tcp_packet.set_sequence(rand::random::<u32>());
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(64240);
        tcp_packet.set_data_offset(8); // include the TS option block

        {
            let packet_bytes = tcp_packet.packet_mut();
            let options = &mut packet_bytes[20..32];
            options.fill(0);
            options[0] = TcpOptionNumbers::TIMESTAMPS.0;
            options[1] = 10; // Option length
            options[2..6].copy_from_slice(&1u32.to_be_bytes()); // TSval
            options[6..10].copy_from_slice(&0u32.to_be_bytes()); // TSecr
                                                                 // Final two bytes remain zero for padding alignment.
        }

        let checksum = calculate_tcp_checksum(&tcp_packet, &source_ip, &target_ip);
        tcp_packet.set_checksum(checksum);

        match tx.send_to(ipv4_packet, IpAddr::V4(target_ip)) {
            Ok(_) => info!("Injected SYN to {}", target_ip),
            Err(e) => error!("Failed to send packet: {}", e),
        }

        // TODO: Replace this jitter with a precomputed schedule; rand in hot loop is noisy.
        let base_interval = interval_ms.load(Ordering::Relaxed).max(1);
        let jitter_cap = base_interval / 5;
        let jitter = if jitter_cap > 0 {
            rand::thread_rng().gen_range(0..=jitter_cap)
        } else {
            0
        };
        let sleep_time = base_interval + jitter;
        thread::sleep(Duration::from_millis(sleep_time));
    }
}

fn find_local_ip(target: Ipv4Addr) -> Option<Ipv4Addr> {
    // UDP connect is the cheapest way to ask the kernel about the egress IP.
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect((target, 80)).ok()?;
    if let std::net::SocketAddr::V4(addr) = socket.local_addr().ok()? {
        Some(*addr.ip())
    } else {
        None
    }
}
