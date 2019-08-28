

extern crate libc;

use libc::{c_int, c_uchar, c_ushort, c_uint, c_ulonglong};

mod ffi_nta;

#[repr(C)]
pub struct PacketNta{
    hash: c_uint,
    data: *mut c_uchar,
    len: c_uint,
    sec: c_uint,
    usec: c_uint,
}

#[repr(C)]
pub struct FlowNta{
    pub iptype: c_uint,// 4-ipv4, 6-ipv6;
    pub sip: [c_uchar; 16],
    pub dip: [c_uchar; 16],
    pub sp: c_ushort,
    pub dp: c_ushort,
    pub proto: c_uchar,
}

pub use self::ffi_nta::{pcap_index_packet_in};