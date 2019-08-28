

#[macro_use]
extern crate log;
extern crate log4rs;


use std::thread;
use std::sync::mpsc::{channel, Receiver, Sender, sync_channel, SyncSender};

mod packet;
mod util;
mod index;
mod data;
mod config;
mod handler;
mod ffi;
mod query;

use crate::config::{config_init, get_config};
use crate::handler::{handler_index_run, Store};
use crate::packet::Packet;

/*
index: |k:file_k|offset...offset|     offset:4Boffset_4Btime
data:  |fh|ph:pd|ph:pd|.......|
*/
pub use crate::ffi::{pcap_index_packet_in};
use std::os::raw::{c_uchar, c_uint};
use std::intrinsics::transmute;
use crate::query::query_server_run;

static mut packet_channel: Option<Vec<(SyncSender<Packet>, Receiver<Packet>)>> = None;
static mut handler_num: u32 = 0;

static mut store_channel: Option<Vec<((SyncSender<Store>, Receiver<Store>))>> = None;

#[no_mangle]
pub extern "C" fn pcap_index_exit(){
    println!("pcap_index_exit.");
}

#[no_mangle]
pub extern "C" fn pcap_index_init(dir: *mut c_uchar, dir_len: c_uint, block_len: c_uint, file_len: c_uint, snaplen: c_uint, packet_chan_len: c_uint, store_chan_len: c_uint, httpserver_c: *mut c_uchar, httpserver_len: c_uint){
    info!("pcap_index_init.");

    let logfile = log4rs::append::file::FileAppender::builder()
        .encoder(Box::new(log4rs::encode::pattern::PatternEncoder::new("{f}:{L} [thread:{T}]: {m}{n}")))
        .build("./pcap_index.log").unwrap();
    let config = log4rs::config::Config::builder()
        .appender(log4rs::config::Appender::builder().build("logfile", Box::new(logfile)))
        .build(log4rs::config::Root::builder().appender("logfile").build(log::LevelFilter::Info)).unwrap();

    log4rs::init_config(config).unwrap();

    info!("config_init.");
    let mut handler_dir = Vec::new();
    handler_dir.extend_from_slice(unsafe { std::slice::from_raw_parts(dir, dir_len as usize)} );

    let mut httpserver = Vec::new();
    httpserver.extend_from_slice(unsafe {std::slice::from_raw_parts(httpserver_c, httpserver_len as usize)});

    config_init(unsafe {String::from_utf8_unchecked(handler_dir)}, block_len as u32, file_len as u32, snaplen as u32,
        unsafe {String::from_utf8_unchecked(httpserver)});

    let config = get_config();
    let handler_path_list:Vec<&str> = config.handler_path.split(' ').collect();

    let mut pc = Vec::new();
    let mut sc = Vec::new();

    for (k, _) in handler_path_list.iter().enumerate(){
        let (ps,pr) = sync_channel(packet_chan_len as usize);
        pc.push((ps, pr));
        let (ss, sr): (SyncSender<Store>, Receiver<Store>) = sync_channel(store_chan_len as usize);
        sc.push((ss, sr));

        unsafe {handler_num += 1;}
    }
    unsafe { packet_channel = Some(pc) };
    unsafe { store_channel = Some(sc) };

    for (k, list) in handler_path_list.into_iter().enumerate() {
        thread::Builder::new().name("pcap_index".to_string() + &k.to_string()).spawn(move || {
            handler_index_run(k, store_chan_len as usize, list.to_owned());
        });
    }

    thread::Builder::new().name("query".to_string()).spawn(move || {
        query_server_run();
    });
}

pub fn get_store_send(index: usize)->&'static SyncSender<Store>{
    unsafe {
        if let Some(sc) = &store_channel{
            let (s,_) = &sc[index%handler_num as usize];
            return s;
        }else{
            error!("get_store_send: store_channel is None.");
            std::process::exit(-1);
        }
    }
}

pub fn get_store_recv(index: usize)->&'static Receiver<Store>{
    unsafe {
        if let Some(sc) = &store_channel{
            let (_,r) = &sc[index%handler_num as usize];
            return r;
        }else{
            error!("get_store_recv: store_channel is None.");
            std::process::exit(-1);
        }
    }
}

pub fn get_packet_send(index: usize)->&'static SyncSender<Packet>{
    unsafe {
        if let Some(pc) = &packet_channel{
            let (s,_) = &pc[index%handler_num as usize];
            return s;
        }else{
            error!("get_packet_send: packet_channel is None.");
            std::process::exit(-1);
        }
    }
}

pub fn get_packet_recv(index: usize)->&'static Receiver<Packet>{
    unsafe {
        if let Some(pc) = &packet_channel{
            let (_,r) = &pc[index%handler_num as usize];
            return r;
        }else{
            error!("get_packet_recv: packet_channel is None.");
            std::process::exit(-1);
        }
    }
}

pub fn get_handler_num()->u32{
    unsafe {
        return handler_num;
    }
}
