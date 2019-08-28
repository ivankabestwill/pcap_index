use std::sync::atomic::AtomicPtr;
use std::intrinsics::transmute;

#[derive(Debug)]
pub struct PcapIndexConfig{
    pub handler_path: String,
    pub data_block_len: u32,
    pub data_file_len: u32,
    pub snaplen: u32,
    pub httpserver: String,
}

pub static mut pcap_index_config: AtomicPtr<PcapIndexConfig> = AtomicPtr::new(std::ptr::null_mut());

pub fn config_init(handler_path: String, block_len: u32, file_len: u32, snaplen: u32, httpserver: String){
    let config = PcapIndexConfig{
      handler_path: handler_path,
        data_block_len: block_len,
        data_file_len: file_len,
        snaplen: snaplen,
        httpserver: httpserver,
    };

    info!("config init with: {:?}", config);

    let box_config = Box::new(config);
    unsafe { pcap_index_config = AtomicPtr::new(transmute::<Box<PcapIndexConfig>, *mut PcapIndexConfig>(box_config)) };
}

pub fn get_config()->&'static PcapIndexConfig{
    let config = unsafe { pcap_index_config.load(std::sync::atomic::Ordering::Relaxed) };
    let config = unsafe { transmute::<*mut PcapIndexConfig, &PcapIndexConfig>(config) };
    return config;
}