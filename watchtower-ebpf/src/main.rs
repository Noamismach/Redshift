#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};

#[map]
static EVENTS: PerfEventArray<u32> = PerfEventArray::new(0);

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const TCP_OPT_TIMESTAMP: u8 = 8;
const TCP_HDR_LEN_MIN: usize = 20;

#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
#[repr(C)]
struct ethhdr {
    h_dest: [u8; 6],
    h_source: [u8; 6],
    h_proto: u16,
}

#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
#[repr(C)]
struct iphdr {
    ihl_version: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
}

#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
#[repr(C)]
struct tcphdr {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    doff_res: u8,
    flags: u8,
    window: u16,
    check: u16,
    urg_ptr: u16,
}

#[classifier]
pub fn watchtower(ctx: TcContext) -> i32 {
    match try_watchtower(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

fn try_watchtower(ctx: TcContext) -> Result<i32, ()> {
    let data_len = ctx.len() as usize;

    let eth_len = mem::size_of::<ethhdr>();
    let eth = load_at::<ethhdr>(&ctx, 0, data_len)?;
    if u16::from_be(eth.h_proto) != ETH_P_IP {
        return Ok(TC_ACT_PIPE);
    }

    let ip_addr = eth_len;
    let ip = load_at::<iphdr>(&ctx, ip_addr, data_len)?;
    if ip.protocol != IPPROTO_TCP {
        return Ok(TC_ACT_PIPE);
    }

    let ip_hdr_size = (ip.ihl_version & 0x0f) as usize * 4;
    if ip_hdr_size < 20 {
        return Err(());
    }
    if ip_addr + ip_hdr_size > data_len {
        return Err(());
    }

    let tcp_addr = ip_addr + ip_hdr_size;
    let tcp = load_at::<tcphdr>(&ctx, tcp_addr, data_len)?;
    let tcp_data_offset = ((tcp.doff_res >> 4) & 0x0f) as usize * 4;
    if tcp_data_offset < TCP_HDR_LEN_MIN {
        return Ok(TC_ACT_PIPE);
    }
    if tcp_data_offset == TCP_HDR_LEN_MIN {
        return Ok(TC_ACT_PIPE);
    }

    // Scan options for TSopt as a heuristic for clock-skew probing.
    let mut offset = tcp_addr + TCP_HDR_LEN_MIN;
    let max_opt_end = tcp_addr + TCP_HDR_LEN_MIN + 40;

    for _ in 0..10 {
        if offset + 1 > data_len || offset >= max_opt_end {
            break;
        }
        let kind = load_at::<u8>(&ctx, offset, data_len)?;

        if kind == 0 {
            break;
        }
        if kind == 1 {
            offset += 1;
            continue;
        }

        if offset + 2 > data_len {
            break;
        }
        let len = load_at::<u8>(&ctx, offset + 1, data_len)? as usize;

        if len < 2 {
            break;
        }
        if offset + len > data_len || offset + len > max_opt_end {
            break;
        }

        if kind == TCP_OPT_TIMESTAMP && len == 10 {
            let src_ip = ip.saddr;
            EVENTS.output(&ctx, &src_ip, 0);
            return Ok(TC_ACT_PIPE);
        }

        offset += len;
        if offset >= tcp_addr + tcp_data_offset {
            break;
        }
    }

    Ok(TC_ACT_PIPE)
}

fn load_at<T: Copy>(ctx: &TcContext, offset: usize, data_len: usize) -> Result<T, ()> {
    let len = mem::size_of::<T>();
    // Required by the eBPF verifier to prove memory-safe packet access.
    if offset + len > data_len {
        return Err(());
    }
    ctx.load::<T>(offset).map_err(|_| ())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
