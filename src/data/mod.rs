
use std::fs::File;
use std::path::Path;
use std::time::SystemTime;
use std::vec::Vec;
use std::sync::atomic::{AtomicPtr};
use std::intrinsics::transmute;
use std::io::{Seek, Write, Read};

use crate::packet::Packet;
use crate::config::{get_config};
use std::net::TcpStream;
use crate::index::{Offset, PcapPacketHeader, PcapFileHeader, FileNameTime};
use crate::util::TransSlice;

pub struct DataFile{
    pub file: File,
    pub offset: u32,
    pub name: FileNameTime,
}

// query use this to get pcap data
#[derive(Debug)]
pub struct DataFileLocation{
    pub file: String,
    pub offset: Vec<Offset>,
}

fn data_file_location_opt(data_file_location: &mut Vec<DataFileLocation>){

    return;
}

pub fn write_stream_back_with_data_file_location(mut datafilelocations: Vec<DataFileLocation>, stream: &mut TcpStream){
    data_file_location_opt(&mut datafilelocations);

    for data_file in datafilelocations{
        info!("read pcap back for stream of file: {:?}", data_file.file);
        let file = File::open(Path::new(&data_file.file));
        if let Ok(mut file) = file{
            for offset in data_file.offset{
                info!("read one offset: {:?}", offset);
                let mut one_read: Vec<u8> = Vec::with_capacity(offset.packet_len as usize);
                unsafe {one_read.set_len(offset.packet_len as usize)};

                match file.seek(std::io::SeekFrom::Start(offset.offset as u64)){
                    Err(e) => {
                        warn!("file seek offset err: {}", e);
                        continue;
                    },
                    Ok(s) => {
                        if s != offset.offset as u64{
                            warn!("file seek offset back err: {}", s);
                            continue;
                        }
                    },
                }
                match file.read(&mut one_read[..]){
                    Err(e) => {
                        warn!("file read offset err: {}", e);
                        continue;
                    },
                    Ok(r) => {
                        if r != offset.packet_len as usize{
                            warn!("file read offset back err: {}", r);
                            continue;
                        }
                    },
                }
                match stream.write(&one_read[..]){
                    Err(e) => {warn!("write back to streasm err: {}", e);continue;},
                    Ok(w) => {
                        if w != offset.packet_len as usize{
                            warn!("write back to stream len err: {}", w);
                            continue;
                        }
                    },
                }
            }
        }
    }

}
pub fn new_datafile(dir: &str)->Option<DataFile>{

    let time_now = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH){
        Ok(t) => {t},
        Err(e) => {error!("new_datafile SystemTime::now().duration_since() err: {}", e); return None;},
    };
    let time_sec: u32 = time_now.as_secs() as u32;
    let time_usec: u32 = time_now.subsec_millis();
    let time: u32 = ((time_sec as u64)*1000 + time_usec as u64) as u32;

    let filename = time.to_string();

    let file_with_dir = dir.to_owned().clone()+"/"+filename.as_str();
    let create_file = Path::new(&file_with_dir);
    let file = match File::create(create_file){
        Ok(t) => {t},
        Err(e) => {error!("new_datafile File::create err: {}", e); return None;},
    };

    let data_file = DataFile{
      file: file,
        offset: 0,
        name: FileNameTime{time: time},
    };

    return Some(data_file);
}

#[derive(Clone)]
pub struct DataBlock{
    data_block: Vec<u8>,
}

pub fn add_pcap_file_header_into_block(data_block: &mut DataBlock)->u32{
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

    unsafe{
        data_block.data_block.extend_from_slice(fileheader.into_slice());
    }

    //info!("pcap file header len: {}", data_block.data_block.len());
    return unsafe { std::mem::size_of::<PcapFileHeader>() as u32};
}

pub fn new_datablock()->DataBlock{

    let config = get_config();

    let mut db = DataBlock{
        data_block: Vec::with_capacity((config.data_block_len + config.snaplen) as usize),
    };

    unsafe { db.data_block.set_len(0) };

    return db;
}

pub fn add_data_into_block(packet: &Packet, data_block: &mut DataBlock, file_offset: &mut u32)->bool{
    let config = get_config();

    let mut offset = data_block.data_block.len() as u32;
    let mut packet_snap_len = packet.data_len as u32;
    if packet_snap_len > config.snaplen{
        packet_snap_len = config.snaplen;
    }

    unsafe {

        let mut header = PcapPacketHeader{
            sec: packet.time.sec,
            usec: packet.time.usec,
            caplen: packet.data_len,
            len: packet.data_len,
        };

        if cfg!(target_endian = "big"){
            header.sec = header.sec.swap_bytes();
            header.usec = header.usec.swap_bytes();
            header.caplen = header.caplen.swap_bytes();
            header.len = header.len.swap_bytes();
        }

        data_block.data_block.extend_from_slice(header.into_slice());
        data_block.data_block.extend_from_slice(&packet.data[..]);
    }

    let packet_len = std::mem::size_of::<PcapPacketHeader>() as u32 + packet_snap_len;

    //info!("packet.data_len: {} packet_len: {}", packet.data_len, packet_len);
    *file_offset += packet_len;

    if offset + packet_len >= config.data_block_len{
        return true;
    }else{
        return false;
    }
}

pub fn write_data_block(data_block: &mut DataBlock, data_file: &mut DataFile){
    if data_block.data_block.len() > 0 {
        data_file.file.write_all(&data_block.data_block[0..]);
        data_file.offset += data_block.data_block.len() as u32;

        unsafe { data_block.data_block.set_len(0) };
    }
}