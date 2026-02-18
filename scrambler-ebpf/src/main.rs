#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::TC_ACT_PIPE,
    helpers::{bpf_csum_diff, bpf_get_prandom_u32},
    macros::classifier,
    programs::TcContext,
};

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod bindings;

use bindings::{ethhdr, iphdr, tcphdr};

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const TCP_OPT_TIMESTAMP: u8 = 8;
const TCP_HDR_LEN_MIN: usize = 20;

#[classifier]
pub fn scrambler(ctx: TcContext) -> i32 {
    match try_scrambler(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_PIPE,
    }
}

fn try_scrambler(mut ctx: TcContext) -> Result<i32, ()> {
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

    let ip_hdr_size = (ip.ihl() & 0x0f) as usize * 4;
    if ip_addr + ip_hdr_size > data_len {
        return Err(());
    }

    let tcp_addr = ip_addr + ip_hdr_size;
    let tcp = load_at::<tcphdr>(&ctx, tcp_addr, data_len)?;
    let tcp_data_offset = (tcp.doff() >> 4) as usize * 4;
    let options_len = tcp_data_offset.saturating_sub(TCP_HDR_LEN_MIN);
    if options_len == 0 {
        return Ok(TC_ACT_PIPE);
    }

    // Walk TCP options to locate TSopt for high-entropy rewrite.
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
            let ts_offset = offset + 2;
            let mut old_ts = load_at::<u32>(&ctx, ts_offset, data_len)?;
            let mut new_ts = unsafe { bpf_get_prandom_u32() }.to_be();

            // Overwrite TSval with high-entropy randomness to collapse linear regression correlation
            // and drive $R^2 -> 0$ for clock-skew inference.
            let diff = unsafe {
                bpf_csum_diff(
                    &mut old_ts as *mut _ as *mut _,
                    4,
                    &mut new_ts as *mut _ as *mut _,
                    4,
                    0,
                )
            };
            if diff < 0 {
                return Ok(TC_ACT_PIPE);
            }

            let csum_offset = tcp_addr + 16;
            ctx.skb
                .l4_csum_replace(csum_offset, 0, diff as u64, 0)
                .map_err(|_| ())?;
            store_at(&mut ctx, ts_offset, data_len, &new_ts)?;
            break;
        }

        offset += len;
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

fn store_at<T>(ctx: &mut TcContext, offset: usize, data_len: usize, v: &T) -> Result<(), ()> {
    let len = mem::size_of::<T>();
    // Required by the eBPF verifier to prove memory-safe packet writes.
    if offset + len > data_len {
        return Err(());
    }
    ctx.store(offset, v, 0).map_err(|_| ())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
