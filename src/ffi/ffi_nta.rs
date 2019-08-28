


use super::{PacketNta, FlowNta};

use crate::packet::{Packet, Flow, Time, Ip, Port, Proto, packet_in};

use std::sync::atomic::AtomicPtr;
use std::mem::transmute;

// communication to nta with: 1) pcap_index compile as lib and call nta function or called by nta directly
//                            2) pcap_index compile as bin and commu with nta by IPC/share memory

#[no_mangle]
pub extern "C" fn pcap_index_packet_in(packet_c: PacketNta, flow_c: FlowNta){

    let time = Time{
        sec: packet_c.sec as u32,
        usec: packet_c.usec as u32,
    };

    let sp = Port{
        port: flow_c.sp as u16,
    };

    let dp = Port{
        port: flow_c.dp as u16,
    };

    let proto = Proto{
        proto: flow_c.proto as u8,
    };

    let mut sip: [u8; 16] = [0; 16];
    let mut dip: [u8; 16] = [0; 16];

    if flow_c.iptype == 4 {
        let sip_ptr = unsafe { transmute::<&u8, *mut u8>(&sip[0]) };
        let dip_ptr = unsafe { transmute::<&u8, *mut u8>(&dip[0]) };
        let flow_c_sip = unsafe { transmute::<&u8, *mut u8>(&flow_c.sip[0] as &u8) };
        let flow_c_dip = unsafe { transmute::<&u8, *mut u8>(&flow_c.dip[0] as &u8) };

        unsafe {
            std::ptr::copy(flow_c_sip, sip_ptr, 4);
            std::ptr::copy(flow_c_dip, sip_ptr, 4);
        }
    }else if flow_c.iptype == 6 {
        let sip_ptr = unsafe { transmute::<&u8, *mut u8>(&sip[0]) };
        let dip_ptr = unsafe { transmute::<&u8, *mut u8>(&dip[0]) };
        let flow_c_sip = unsafe { transmute::<&u8, *mut u8>(&flow_c.sip[0] as &u8) };
        let flow_c_dip = unsafe { transmute::<&u8, *mut u8>(&flow_c.dip[0] as &u8) };

        unsafe{
            std::ptr::copy(flow_c_sip, sip_ptr, 16);
            std::ptr::copy(flow_c_dip, sip_ptr, 16);
        }
    }else{
        warn!("packet_in_from_nta_raw_call iptype wrong.");
        return;
    }


    let mut packet = Packet{
        hash: packet_c.hash as u32,
        data: Vec::with_capacity(packet_c.len as usize),
        data_len: packet_c.len as u32,
        time: time,
        flow: Flow{sp: sp, dp: dp, proto: proto,  sip: Ip{ip: sip}, dip: Ip{ip: dip}},
    };
    packet.data.extend_from_slice(unsafe { std::slice::from_raw_parts(packet_c.data, packet_c.len as usize) });

    packet_in(packet);
}