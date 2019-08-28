
use std::sync::atomic::AtomicPtr;
use crate::{get_packet_send};
use crate::util::{TransSliceLen, TransSlice};

pub struct Time{
    pub sec: u32,
    pub usec: u32,
}

#[derive(Eq, PartialEq, Hash, Clone, Copy, Debug, Default)]
pub struct Ip{
    pub ip: [u8; 16],//ipv4 4Byte, ipv6 16Byte
}

#[derive(Eq, PartialEq, Hash, Clone, Copy, Debug, Default)]
pub struct Port{
    pub port: u16,
}

#[derive(Eq, PartialEq, Hash, Clone, Copy, Debug, Default)]
pub struct Proto{
    pub proto: u8,
}

impl TransSliceLen for Ip{}
impl TransSliceLen for Port{}
impl TransSliceLen for Proto{}
impl TransSlice for Ip{}
impl TransSlice for Port{}
impl TransSlice for Proto{}

pub struct Flow{
    pub sip: Ip,
    pub dip: Ip,
    pub sp: Port,
    pub dp: Port,
    pub proto: Proto,
}

pub struct Packet{
    pub hash: u32,
    pub flow: Flow,
    pub time: Time,
    pub data: Vec<u8>,
    pub data_len: u32,
}


pub fn packet_in(packet: Packet){
    let input = get_packet_send(packet.hash as usize);
    input.send(packet).unwrap();
}
