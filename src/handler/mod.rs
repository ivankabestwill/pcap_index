// one handler: one receive thread and one store thread

extern crate leveldb_rs;

use leveldb_rs::{DB};

use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender, sync_channel, SyncSender};
use crate::packet::{Packet};
use crate::data::DataBlock;
use crate::index::{Index, new_dataindex, index_packet, Offset, FileNameTime};
use crate::data::{new_datafile, add_data_into_block, new_datablock, DataFile, write_data_block, DataFileLocation, add_pcap_file_header_into_block};
use std::thread;
use std::os::unix::ffi::OsStrExt;

use crate::config::{get_config};
use std::intrinsics::transmute;
use crate::get_packet_recv;
use crate::query::{Query};
use crate::{get_store_send, get_store_recv, get_handler_num};
use crate::util::TransSlice;

pub enum Store{
    block((DataBlock)),
    index((Index)),
    query((Query, SyncSender<Option<Vec<DataFileLocation>>>)),
}

pub fn write_index(index: &Index, data_file: &DataFile, db: &mut DB){

    let mut filename = Vec::from(data_file.name.into_slice());

    for (k,v) in &index.sip{
        let mut k_file: Vec<u8> = Vec::new();
        k_file.extend_from_slice(&filename[..]);
        let ip_slice = &v.ip.ip[..];
        k_file.extend_from_slice(ip_slice);

        let mut ip_offset: Vec<u8> = Vec::new();

        for offset in &v.offset{
            ip_offset.extend_from_slice(offset.into_slice());
        }

        //info!("db.put ip_start {:?} {:?}", &k_file[..], &ip_offset[..]);
        if let Err(_)  = db.put(&k_file[..], &ip_offset[..]){
            warn!("leveldb db.put err");
        }
    }

    for (k,v) in &index.dip{
        let mut k_file: Vec<u8> = Vec::new();
        let ip_slice = &v.ip.ip[..];

        k_file.extend_from_slice(&filename[..]);
        k_file.extend_from_slice(ip_slice);

        let mut ip_offset: Vec<u8> = Vec::new();

        for offset in &v.offset{
            ip_offset.extend_from_slice(offset.into_slice());
        }

        if let Err(_)  = db.put(&k_file[..], &ip_offset[..]){
            warn!("leveldb db.put err");
        }
    }

    for (k,v) in &index.sp{
        let mut k_file: Vec<u8> = Vec::new();

        k_file.extend_from_slice(&filename[..]);
        k_file.extend_from_slice(v.port.into_slice());

        let mut port_offset: Vec<u8> = Vec::new();

        for offset in &v.offset{
            port_offset.extend_from_slice(offset.into_slice());
        }

        if let Err(_)  = db.put(&k_file[..], &port_offset[..]){
            warn!("leveldb db.put err");
        }
    }

    for (k,v) in &index.dp{
        let mut k_file: Vec<u8> = Vec::new();

        k_file.extend_from_slice(&filename[..]);
        k_file.extend_from_slice(v.port.into_slice());

        let mut port_offset: Vec<u8> = Vec::new();

        for offset in &v.offset{
            port_offset.extend_from_slice(offset.into_slice());
        }

        if let Err(_)  = db.put(&k_file[..], &port_offset[..]){
            warn!("leveldb db.put err");
        }
    }

    for (k,v) in &index.proto{
        let mut k_file: Vec<u8> = Vec::new();

        k_file.extend_from_slice(&filename[..]);
        k_file.extend_from_slice(v.proto.into_slice());

        let mut proto_offset: Vec<u8> = Vec::new();

        for offset in &v.offset{
            proto_offset.extend_from_slice(offset.into_slice());
        }

        if let Err(_)  = db.put(&k_file[..], &proto_offset[..]){
            warn!("leveldb db.put err");
        }
    }

}

// store packet into block and set packet index
// if block is enough send block to store handler
// if file is enough send index to store handler
pub fn handler_index_run(handler_index: usize, store_chan_len: usize, handler_root: String) {
    let config = get_config();

    let store_send = get_store_send(handler_index);

    let store_thread = thread::Builder::new().name("pcap_store".to_string()+&handler_index.to_string()).spawn( move || {
        handler_store_run(handler_index, handler_root);
    });

    let input = get_packet_recv(handler_index);

    loop {
        let mut index: Index = new_dataindex();
        let mut data_block: DataBlock = new_datablock();

        let mut file_offset: u32 = add_pcap_file_header_into_block(&mut data_block);

        loop{
            if let Ok(packet) = input.recv() {
                // index this packet
                index_packet(&packet, file_offset, &mut index);

                // add this packet into block buffer
                let block_full = add_data_into_block(&packet, &mut data_block, &mut file_offset);

                if block_full{
                    // data block is fully, send to thread_store.
                    store_send.send(Store::block(data_block)).unwrap();
                    data_block = new_datablock();
                }

                // if file len enough, flush index, and create new file.
                //info!("file_offset: {} cnofig.data_file_len: {}", file_offset, config.data_file_len);
                if file_offset >= config.data_file_len{
                    store_send.send(Store::block(data_block)).unwrap();
                    store_send.send(Store::index(index)).unwrap();
                    break;
                }
            }else{
                error!("handler_index_run input.recv err.");
                std::process::exit(-1);
            }
        }
    }
}

// store block data into disk or accept query
fn handler_store_run(handler_index: usize, handler_root: String){

    let input = get_store_recv(handler_index);
    let config = get_config();

    let handler_dir = handler_root + "handler" + &handler_index.to_string();

    let mut cd = std::fs::DirBuilder::new();
    cd.create(Path::new(&handler_dir));

    let handler_data_dir = handler_dir.clone() + "/data";
    let handler_index_dir = handler_dir.clone() + "/index";
    cd.create(Path::new(&handler_data_dir));
    cd.create(Path::new(&handler_index_dir));

    let mut file_list: Vec<String> = Vec::new();
    if let Ok(data_dir) = std::fs::read_dir(&handler_data_dir){
        for dir in data_dir.into_iter(){
            if let Ok(one_file) = dir{
                if let Ok(filename) = one_file.file_name().into_string(){
                    file_list.push(filename);
                }
            }
        }
    }else{
        error!("handler {} read_dir not exist.", handler_index);
        std::process::exit(-1);
    }

    let db_path = Path::new(&handler_index_dir);
    let mut db = match DB::open(db_path) {
        Ok(t) => { t },
        Err(e1) => {
            match DB::create(db_path) {
                Ok(t) => { t },
                Err(e2) => {
                    error!("leveldb create err {} after open err {}", e2, e1);
                    std::process::exit(-1);
                },
            }
        },
    };

    loop {
        let mut data_file: DataFile = match new_datafile(&handler_data_dir) {
            Some(t) => { t },
            None => {
                error!("new_datafile err.");
                std::process::exit(-1);
            },
        };

        loop{
            if let Ok(store) = input.recv(){
                match store{
                    Store::block(mut data_block) => {write_data_block(&mut data_block, &mut data_file);},
                    Store::index(index) => {write_index(&index, &data_file, &mut db); data_file.file.sync_all();break;},
                    Store::query((query, query_back)) => {
                        handle_query(query, query_back, &db, &file_list, &handler_data_dir);
                    },
                }
            }else{
                error!("handler_store_run input.recv err.");
                std::process::exit(-1);
            }
        }

        file_list.push(data_file.name.time.to_string());
    }
}

fn do_query(query: &[u8], db: &DB)->Option<Vec<Offset>>{
    let offset_size = 10;
    let mut query_offset:Vec<Offset> = Vec::new();

    if let Ok(query_result) = db.get(query){
        if let Some(offset_list) = query_result{
            info!("db.get raw slice: {:?}", offset_list);
            let offset_num = offset_list.len()/offset_size;
            for i in 0..offset_num{
                let offset = &offset_list[i*offset_size..(i+1)*offset_size];
                let offset = Offset::from_slice(offset);
                query_offset.push(offset);
            }
        }else{
            return None;
        }
    }else{
        return None;
    }

    return Some(query_offset);
}

//
fn min_offset(offseta: Vec<Offset>, offsetb: Vec<Offset>)->Option<Vec<Offset>>{
    let mut offset = Vec::new();

    for offset1 in &offseta{
        for offset2 in &offsetb{
            if offset1.offset < offset2.offset{
                break;
            }
            if offset1.offset == offset2.offset{
                offset.push(*offset1);
            }
        }
    }

    if offset.len() > 0{
        return Some(offset);
    }

    return None;
}

fn min_query_offset(offset1: Option<Vec<Offset>>, offset2: Option<Vec<Offset>>)-> Option<Vec<Offset>>{
    if let Some(offset1) = offset1{
        if let Some(offset2) = offset2{
            let min = min_offset(offset1,offset2);
            return min;
        }else{
            return Some(offset1);
        }
    }else{
        if let Some(offset2) = offset2{
            return Some(offset2);
        }
    }

    return None;
}

fn query_into_datafilelocation(offset: Vec<Offset>, filename: &str, filepath: &str)->DataFileLocation{

    let file = filepath.to_owned().clone()+"/"+filename;
    let data_file_loction = DataFileLocation{
        offset: offset,
        file: file,
    };

    return data_file_loction;
}

fn handle_query(query: Query, query_back: SyncSender<Option<Vec<DataFileLocation>>>, db: &DB, file_list: &Vec<String>, filepath: &str){

    info!("handler_query.");
    let mut data_file_location: Vec<DataFileLocation> = Vec::new();

    for filename in file_list{
        info!("query for file: {}", filename);

        let mut filetime = FileNameTime{time: 0};
        if let Ok(ft) = filename.parse::<u32>(){
            filetime.time = ft;
        }else{
            continue;
        }

        let mut  query_offset = None;

        // get ip_start offset
        let mut query_ip_start = None;
        if let Some(ip_start) = query.ip_start{
            let mut query_slice = Vec::new();
            query_slice.extend_from_slice(filetime.into_slice());
            query_slice.extend_from_slice(ip_start.into_slice());
            query_ip_start = do_query(&query_slice[..], db);
            if let None = query_ip_start{
                info!("query ip_start None.");
                continue;
            }
            info!("db.get ip_start: {:?} {:?}", query_slice, query_ip_start);
        }
        query_offset = min_query_offset(query_offset, query_ip_start);
        info!("query ip_start: {:?}", query_offset);

        // get ip_end offset
        let mut query_ip_end = None;
        if let Some(ip_end) = query.ip_end{
            let mut query_slice = Vec::new();
            query_slice.extend_from_slice(filetime.into_slice());
            query_slice.extend_from_slice(ip_end.into_slice());
            query_ip_end = do_query(&query_slice[..], db);
            if let None = query_ip_end{
                info!("query ip_end None.");
                continue;
            }
        }
        query_offset = min_query_offset(query_offset, query_ip_end);
        //info!("query ip_end: {:?}", query_offset);

        // get port_start offset
        let mut query_port_start = None;
        if let Some(port_start) = query.ip_end{
            let mut query_slice = Vec::new();
            query_slice.extend_from_slice(filetime.into_slice());
            query_slice.extend_from_slice(port_start.into_slice());
            query_port_start = do_query(&query_slice[..], db);
            if let None = query_port_start{
                info!("query port_start None.");
                continue;
            }
        }
        query_offset = min_query_offset(query_offset, query_port_start);
        //info!("query port_start: {:?}", query_offset);

        // get port_end offset
        let mut query_port_end = None;
        if let Some(port_end) = query.ip_end{
            let mut query_slice = Vec::new();
            query_slice.extend_from_slice(filetime.into_slice());
            query_slice.extend_from_slice(port_end.into_slice());
            query_port_end = do_query(&query_slice[..], db);
            if let None = query_port_end{
                info!("query port_end None.");
                continue;
            }
        }
        query_offset = min_query_offset(query_offset, query_port_end);
        //info!("query port_end: {:?}", query_offset);

        // get proto offset
        let mut query_proto = None;
        if let Some(proto) = query.ip_end{
            let mut query_slice = Vec::new();
            query_slice.extend_from_slice(filetime.into_slice());
            query_slice.extend_from_slice(proto.into_slice());
            query_proto = do_query(&query_slice[..], db);
            if let None = query_proto{
                info!("query proto offset None.");
                continue;
            }
        }
        query_offset = min_query_offset(query_offset, query_proto);
        //info!("query proto: {:?}", query_offset);

        if let Some(query_offset) = query_offset{
            if query_offset.len() > 0 {
                let dfl = query_into_datafilelocation(query_offset, filename, filepath);
                info!("build one query offset with file into DataFileLocation: {:?}", dfl);
                data_file_location.push(dfl);
            }
        }else{
            continue;
        }
    }

    if data_file_location.len() > 0{
        info!("send DataFileLocation back to query.");
        query_back.send(Some(data_file_location));
        return;
    }else{
        query_back.send(None);
        return;
    }
}

// share memory way to get packet from nta
fn handler_receive_run(output: Sender<DataBlock>){

}

