
extern crate http;

use http::Uri;

use std::str::FromStr;
use std::net::{TcpListener, TcpStream, IpAddr, Ipv4Addr, Ipv6Addr};
use std::io::{Read,Write};
use std::collections::VecDeque;

use crate::packet::{Ip, Port, Proto};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use crate::handler::{Store};
use crate::data::{DataFileLocation, write_stream_back_with_data_file_location};
use crate::{get_handler_num, get_store_recv, get_store_send};
use crate::get_config;
use crate::index::{new_pcap_file_header};
use crate::util::TransSlice;
/*
http://ip:port/packet/query?ip=1.2.3.4-2.3.4.5&port=53-1521&proto=6&time=33333333-5555555
              |  path      | query key-value
              time=time.now().sec*1000 + time.now().usec;
*/

#[derive(Copy, Clone, Debug)]
pub struct Query{
    pub ip_start: Option<Ip>,
    pub ip_end: Option<Ip>,
    pub port_start: Option<Port>,
    pub port_end: Option<Port>,
    pub proto: Option<Proto>,
    pub time_start: Option<u32>,
    pub time_end: Option<u32>,
}

pub fn query_server_run(){
    let config = get_config();

    let listener = match TcpListener::bind(&config.httpserver){
        Ok(t) => {t},
        Err(e) => {
            error!("query_server_run TcpListener::bind err: {}", e);
            std::process::exit(-1);
        },
    };

    loop{
        if let Ok((mut stream, _)) = listener.accept(){
                info!("pcap_indx get one query");
                stream.write(b"HTTP/1.1 200 OK\r\n\r\n");
                let file_header = new_pcap_file_header();
                stream.write(file_header.into_slice());
                handle_one_stream(&mut stream);
        }else{
            warn!("TcpListener accept err");
        }
    }
}

fn handle_one_stream(stream: &mut TcpStream){

    info!("handle_one_stream query.");
    let mut input_vec = Vec::with_capacity(1000000);
    unsafe {input_vec.set_len(1000000)};

    if let Ok(rl) = stream.read(&mut input_vec[..]){
        let input = match String::from_utf8(Vec::from(&input_vec[0..rl])){
            Ok(t) => {t},
            Err(_)=> {warn!("string from utf8 err."); return;}
        };

        info!("query: {:?}", input);
        let get_uri: Vec<&str> = input.split(' ').collect();
        if get_uri[0] != "GET"{
            warn!("we only accept GET");
            return;
        }

        if let Ok(uri) = get_uri[1].parse::<Uri>(){
            info!("uri: {:?}", uri);
            let path = uri.path();

            let key_values = match uri.query(){
                Some(t) => {t},
                None => {warn!("not support query without key-value.");return;},
            };

            info!("query path: {} key-value: {}", path, key_values);
            let key_value: Vec<&str> = key_values.split('&').collect();

            let mut ip: VecDeque<&str> = VecDeque::new();
            let mut port: VecDeque<&str> = VecDeque::new();
            let mut proto: VecDeque<&str> = VecDeque::new();
            let mut time: VecDeque<&str> = VecDeque::new();

            for kv in key_value.into_iter(){
                if let Some(_) = kv.find("ip="){
                    let ips: Vec<&str> = kv.split('=').collect();
                    let ips: Vec<&str> = ips[1].split('-').collect();

                    for i in ips.into_iter(){
                        ip.push_back(i);
                    }
                }else if let Some(_) = kv.find("port="){
                    let ports: Vec<&str> = kv.split('=').collect();
                    let ports: Vec<&str> = ports[1].split('-').collect();

                    for i in ports.into_iter(){
                        port.push_back(i);
                    }
                }else if let Some(_) = kv.find("time="){
                    let times: Vec<&str> = kv.split('=').collect();
                    let times: Vec<&str> = times[1].split('-').collect();

                    for i in times.into_iter(){
                        time.push_back(i);
                    }
                }else if let Some(_) = kv.find("proto="){
                    let protos: Vec<&str> = kv.split('=').collect();
                    proto.push_back(protos[1]);
                }
            }

            if ip.len() == 0 && port.len() == 0 && proto.len() == 0 && time.len() == 0{
                // atleast one condition.
                warn!("query condition is not exist, all pcap files is too big, not support.");
                return;
            }

            if ip.len() > 2 || port.len() > 2 || proto.len() > 1 || time.len() > 2{
                warn!("query condition format err");
                return;
            }

            stream_back_pcap_file_with_condition(stream, ip, port, proto, time);
        }else{
            warn!("query uri err.");
        }
    }else{
        warn!("TcpStream read err.");
    }
}



fn stream_back_pcap_file_with_condition(stream: &mut TcpStream, ip: VecDeque<&str>, port: VecDeque<&str>, proto: VecDeque<&str>, time: VecDeque<&str>){
   let (mut ip_start, mut ip_end) = (None, None);

    if ip.len() != 0{
       match Ipv4Addr::from_str(ip[0]) {
           Ok(s) => {
               if ip.len() == 2 {
                   let e = match Ipv4Addr::from_str(ip[1]) {
                       Ok(e) => { e },
                       Err(_) => {
                           error!("Ipv4Addr err: {:?}", ip);
                           return;
                       }
                   };
                   ip_start = Some(IpAddr::V4(s));
                   ip_end = Some(IpAddr::V4(e));
               } else {
                   ip_start = Some(IpAddr::V4(s));
                   ip_end = None;
               }
           },
           Err(_) => {
               if ip.len() == 2 {
                   let s = match Ipv6Addr::from_str(ip[0]) {
                       Ok(s) => { s },
                       Err(_) => {
                           error!("Ipv6Addr err: {:?}", ip);
                           return;
                       }
                   };
                   let e = match Ipv6Addr::from_str(ip[1]) {
                       Ok(s) => { s },
                       Err(_) => {
                           error!("Ipv6Addr err: {:?}", ip);
                           return;
                       }
                   };
                   ip_start = Some(IpAddr::V6(s));
                   ip_end = Some(IpAddr::V6(e));
               } else {
                   let s = match Ipv6Addr::from_str(ip[0]) {
                       Ok(s) => { s },
                       Err(_) => {
                           error!("Ipv6Addr err: {:?}", ip);
                           return;
                       }
                   };
                   ip_start = Some(IpAddr::V6(s));
                   ip_end = None;
               }
           },
       }
   }else{
        ip_start = None;
        ip_end = None;
   }

    let (mut port_start, mut port_end) = (None, None);

    if port.len() == 1{
        if let Ok(s) = port[0].parse::< u16 > (){
            port_start = Some(Port{port: s});
            port_end = None;
        }else{
            warn ! ("port format err");
            return;
        }
    }else if port.len() == 2{
        if let Ok(s) = port[0].parse::< u16 > (){
            if let Ok(e) = port[1].parse::< u16 > (){
                port_start = Some(Port{ port: s});
                port_end = Some(Port{port: e});
            }else{
                warn ! ("port format err.");
                return;
            }
        }else{
            warn ! ("port format err");
            return;
        }
    }else if port.len() == 0{
        port_start = None;
        port_end = None;
    }

    let mut local_proto = None;
    if proto.len() == 1 {
        let local_proto = match proto[0].parse::<u8>() {
            Ok(t) => {
                local_proto = Some(Proto { proto: t });
            },
            Err(_) => {
                warn!("port format err.");
                return;
            },
        };
    }

    let (mut time_start, mut time_end) = (None, None);

    if time.len()==1{
        if let Ok(s) = time[0].parse::<u32>(){
            time_start = Some(s);
            time_end = None;
        }else{
            warn!("port format err");
            return;
        }
    }else if time.len() ==2{
        if let Ok(s) = time[0].parse::<u32>(){
            if let Ok(e) = time[1].parse::<u32>(){
                time_start = Some(s);
                time_end = Some(e);
            }else{
                warn!("port format err.");
                return;
            }
        }else{
            warn!("port format err");
            return;
        }
    }else if time.len() == 0{
        time_start = None;
        time_end = None;
    }


    let ip_start_slice = if let Some(s) = ip_start{
        match s{
            IpAddr::V4(s4) => {
                let s4 = s4.octets();
                let mut ip_array:[u8; 16] = [0;16];
                ip_array[0]=s4[0];
                ip_array[1]=s4[1];
                ip_array[2]=s4[2];
                ip_array[3]=s4[3];
                Some(Ip{ip: ip_array})
            },
            IpAddr::V6(s6) => {
                let ip_array = s6.octets();
                Some(Ip{ip: ip_array})
            }
        }
    }else{
        None
    };
    let ip_end_slice = if let Some(s) = ip_end{
        match s{
            IpAddr::V4(s4) => {
                let s4 = s4.octets();
                let mut ip_array:[u8; 16] = [0;16];
                ip_array[0]=s4[0];
                ip_array[1]=s4[1];
                ip_array[2]=s4[2];
                ip_array[3]=s4[3];
                Some(Ip{ip: ip_array})
            },
            IpAddr::V6(s6) => {
                let ip_array = s6.octets();
                Some(Ip{ip: ip_array})
            }
        }
    }else{
        None
    };

    let query = Query{
      ip_start: ip_start_slice,
        ip_end: ip_end_slice,
        port_start: port_start,
        port_end: port_end,
        time_start: time_start,
        time_end: time_end,
        proto: local_proto,
    };

    info!("query is: {:?}", query);

    let handlers = get_handler_num();
    let mut query_result: Vec<(SyncSender<Option<Vec<DataFileLocation>>>, Receiver<Option<Vec<DataFileLocation>>>)> = Vec::new();

    for index in 0..handlers{
        let result = sync_channel(1);
        query_result.push(result);
    }

    for (index, (s,r)) in query_result.iter().enumerate(){
        let store_query = Store::query((query, s.clone()));
        let query_send = get_store_send(index as usize);
        query_send.send(store_query);
    }

    for (_, result) in query_result{
        if let Ok( datafilelocation) = result.recv(){
            if let Some(datafilelocations) = datafilelocation{
                info!("do read file data and write back to stream.");
                write_stream_back_with_data_file_location(datafilelocations, stream);
            }
        }else{
            error!("query get DataFileLocation err.");
            std::process::exit(-1);
        }
    }

    stream.flush();
}