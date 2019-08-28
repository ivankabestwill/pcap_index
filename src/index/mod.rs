
extern crate leveldb_rs;
extern crate libc;

use leveldb_rs::{DB};
use libc::{c_uint};

use std::vec::Vec;
use std::collections::HashMap;

use crate::packet::{Ip, Port, Proto, Packet};
use crate::data::{DataFile};
use std::os::raw::c_ushort;
use crate::util::{TransSlice, TransSliceLen};
use crate::config::{get_config};

#[repr(C)]
#[derive(Default)]
pub struct PcapPacketHeader{
    pub sec: u32,
    pub usec: u32,
    pub caplen: u32,
    pub len: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct PcapFileHeader{
    pub magic: u32,
    pub version_maj: u16,
    pub version_min: u16,
    pub thiszone: u32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub linktype: u32,
}
impl TransSliceLen for PcapPacketHeader{}
impl TransSliceLen for PcapFileHeader{}
impl TransSlice for PcapFileHeader{}
impl TransSlice for PcapPacketHeader{}

#[derive(Default)]
pub struct FileNameTime{
    pub time: u32,
}

impl TransSliceLen for FileNameTime{}
impl TransSlice for FileNameTime{}

// data file max 4GB length
#[derive(Copy, Clone, Default, Debug)]
pub struct Offset{
    pub offset: u32,
    pub time: u32,
    pub packet_len: u16
}

impl TransSliceLen for Offset{
    fn slice_len(&self)->usize{
        return 10;
    }
}
impl TransSlice for Offset{}

pub struct IndexIp{
    pub ip: Ip,
    pub offset: Vec<Offset>,
}

pub struct IndexPort{
    pub port: Port,
    pub offset: Vec<Offset>,
}

pub struct IndexProto{
    pub proto: Proto,
    pub offset: Vec<Offset>,
}

fn new_offset(offset: u32, time: u32, packet_len: u16)->Offset{
    let offset = Offset{
        offset: offset,
        time: time,
        packet_len: packet_len,
    };

    return offset;
}
fn new_indexip(ip: Ip)->IndexIp{
    let indexip = IndexIp{
      ip: ip,
        offset: Vec::new(),
    };

    return indexip;
}

fn new_indexport(port: Port)->IndexPort{
    let indexport = IndexPort{
        port: port,
        offset: Vec::new(),
    };

    return indexport;
}

fn new_indexproto(proto: Proto)->IndexProto{
    let indexproto = IndexProto{
        proto: proto,
        offset: Vec::new(),
    };

    return indexproto;
}

pub struct Index{
    pub sip: HashMap<Ip, IndexIp>,
    pub dip: HashMap<Ip, IndexIp>,
    pub sp: HashMap<Port, IndexPort>,
    pub dp: HashMap<Port, IndexPort>,
    pub proto: HashMap<Proto, IndexProto>,
}

fn read_from_leveldb(k: &[u8])->Option<Vec<u8>>{

    return None;
}

pub fn new_dataindex()->Index{
    let di = Index{
        sip: HashMap::new(),
        dip: HashMap::new(),
        sp: HashMap::new(),
        dp: HashMap::new(),
        proto: HashMap::new(),
    };

    return di;
}

pub fn index_sip(sip: Ip, offset: u32, time: u32, packet_len: u16, index: &mut Index){
    match index.sip.get_mut(&sip){
        Some(index_sip) => {
            index_sip.offset.push(new_offset(offset, time, packet_len));
        },
        None => {
            let mut index_sip = new_indexip(sip);
            index_sip.offset.push(new_offset(offset, time, packet_len));
            index.sip.insert(sip, index_sip);
        },
    }
}

pub fn index_dip(dip: Ip, offset: u32, time: u32, packet_len: u16, index: &mut Index){
    match index.dip.get_mut(&dip){
        Some(index_dip) => {
            index_dip.offset.push(new_offset(offset, time, packet_len));
        },
        None => {
            let mut index_dip = new_indexip(dip);
            index_dip.offset.push(new_offset(offset, time, packet_len));
            index.dip.insert(dip, index_dip);
        },
    }
}
pub fn index_sp(sp: Port, offset: u32, time: u32, packet_len: u16, index: &mut Index){
    match index.sp.get_mut(&sp){
        Some(index_sp) => {
            index_sp.offset.push(new_offset(offset, time, packet_len));
        },
        None => {
            let mut index_sp = new_indexport(sp);
            index_sp.offset.push(new_offset(offset, time, packet_len));
            index.sp.insert(sp, index_sp);
        },
    }
}
pub fn index_dp(dp: Port, offset: u32, time: u32, packet_len: u16, index: &mut Index){
    match index.dp.get_mut(&dp){
        Some(index_dp) => {
            index_dp.offset.push(new_offset(offset, time, packet_len));
        },
        None => {
            let mut index_dp = new_indexport(dp);
            index_dp.offset.push(new_offset(offset, time, packet_len));
            index.dp.insert(dp, index_dp);
        },
    }
}
pub fn index_proto(proto: Proto, offset: u32, time: u32, packet_len: u16, index: &mut Index){
    match index.proto.get_mut(&proto){
        Some(index_proto) => {
            index_proto.offset.push(new_offset(offset, time, packet_len));
        },
        None => {
            let mut index_proto = new_indexproto(proto);
            index_proto.offset.push(new_offset(offset, time, packet_len));
            index.proto.insert(proto, index_proto);
        },
    }
}

pub fn index_packet(packet: &Packet, file_offset: u32, index: &mut Index){
    let sip = packet.flow.sip;
    let dip = packet.flow.dip;
    let sp = packet.flow.sp;
    let dp = packet.flow.dp;
    let proto = packet.flow.proto;
    let offset = file_offset;
    let packet_len: u16 = packet.data_len as u16 + std::mem::size_of::<PcapPacketHeader>() as u16;
    let time = ((packet.time.sec as u64)*1000 + packet.time.usec as u64) as u32;

    index_sip(sip, offset, time, packet_len, index);
    index_dip(dip, offset, time, packet_len, index);
    index_sp(sp, offset, time, packet_len, index);
    index_dp(dp, offset, time, packet_len, index);
    index_proto(proto, offset, time, packet_len, index);
}


pub fn new_pcap_file_header()->PcapFileHeader{
    let config = get_config();

    let mut fileheader = PcapFileHeader{
        magic: 0xa1b2c3d4,
        version_maj: 2,
        version_min: 4,
        thiszone: 0,
        sigfigs: 0,
        snaplen: config.snaplen,
        linktype: 1,
    };

    if cfg!(target_endian = "big"){
        fileheader.magic = fileheader.magic.swap_bytes();
        fileheader.version_maj = fileheader.version_maj.swap_bytes();
        fileheader.version_min = fileheader.version_min.swap_bytes();
        fileheader.snaplen = fileheader.snaplen.swap_bytes();
        fileheader.linktype = fileheader.linktype.swap_bytes();
    }

    return fileheader;
}