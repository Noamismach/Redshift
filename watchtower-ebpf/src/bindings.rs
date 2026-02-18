#![allow(non_upper_case_globals)]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(dead_code)]

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ethhdr {
    pub h_dest: [u8; 6],
    pub h_source: [u8; 6],
    pub h_proto: u16,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct iphdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

impl iphdr {
    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0f
    }
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct tcphdr {
    pub source: u16,
    pub dest: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub doff_res: u8,
    pub flags: u8,
    pub window: u16,
    pub check: u16,
    pub urg_ptr: u16,
}

impl tcphdr {
    pub fn doff(&self) -> u8 {
        self.doff_res
    }
}
