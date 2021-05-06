#[cfg(target_os = "android")]
use android_logger::Config;
use common::{
    decode_ipv4, hdr_to_key, key_to_hdr,
    nxthdr::{nxt_hdr::Hdr, nxt_hdr::StreamOp, NxtHdr, NxtOnboard},
    parse_host,
    tls::parse_sni,
    FlowV4Key, NxtBufs, NxtErr, RegType, Transport, NXT_OVERHEADS,
};
#[cfg(target_os = "linux")]
use counters::Counters;
use dummy::Dummy;
use fd::Fd;
use l3proxy::Socket;
use log::{error, Level, LevelFilter};
use mio::{Events, Poll, Token};
use netconn::NetConn;
#[cfg(target_vendor = "apple")]
use oslog::OsLogger;
#[cfg(target_os = "linux")]
use perf::Perf;
use std::os::raw::{c_char, c_int};
use std::slice;
use std::{collections::HashMap, time::Duration};
use std::{collections::VecDeque, time::Instant};
use std::{ffi::CStr, usize};
use std::{sync::atomic::AtomicI32, sync::atomic::AtomicUsize};
use webproxy::WebProxy;
use websock::WebSession;

// Note1: The "vpn" seen in this file refers to the tun interface from the OS on the device
// to our agent. Its bascailly the "vpnService" tunnel or the networkExtention/packetTunnel
// in ios.

// These are atomic because rust will complain loudly about mutable global variables
static VPNFD: AtomicI32 = AtomicI32::new(0);
static DIRECT: AtomicI32 = AtomicI32::new(0);
static mut REGINFO: Option<Box<RegistrationInfo>> = None;
static REGINFO_CHANGED: AtomicUsize = AtomicUsize::new(0);

static STATS_GWUP: AtomicI32 = AtomicI32::new(0);
static STATS_NUMFLAPS: AtomicI32 = AtomicI32::new(0);
static STATS_LASTFLAP: AtomicI32 = AtomicI32::new(0);
static STATS_NUMFLOWS: AtomicI32 = AtomicI32::new(0);
static STATS_GWFLOWS: AtomicI32 = AtomicI32::new(0);

const NXT_AGENT_PROXY: usize = 8080;

const UNUSED_IDX: usize = 0;
const VPNTUN_IDX: usize = 1;
const WEBPROXY_IDX: usize = 2;
const GWTUN_IDX: usize = 3;
const TUN_START: usize = 4;
const UNUSED_POLL: Token = Token(UNUSED_IDX);
const VPNTUN_POLL: Token = Token(VPNTUN_IDX);
const WEBPROXY_POLL: Token = Token(WEBPROXY_IDX);
const GWTUN_POLL: Token = Token(GWTUN_IDX);
// TODO: Make this to be variable based on the agent.pktmem setting of the platform
const MAX_PENDING_RX: usize = 1;

const CLEANUP_NOW: usize = 5; // 5 seconds
const CLEANUP_TCP_HALFOPEN: usize = 30; // 30 seconds
const CLEANUP_TCP_IDLE: usize = 60 * 60; // one hour
const CLEANUP_UDP_IDLE: usize = 4 * 60; // 4 minutes
const CLEANUP_UDP_DNS: usize = 10; // 10 seconds
const MONITOR_IDLE_BUFS: u64 = 1; // 1 seconds
const MONITOR_FLOW_AGE: u64 = 30; // 30 seconds
const MONITOR_CONNECTIONS: u64 = 2; // 2 seconds
const PARSE_MAX: usize = 2048;
const SERVICE_PARSE_TIMEOUT: u64 = 100; // milliseconds

#[derive(Default, Debug)]
pub struct RegistrationInfo {
    host: String,
    access_token: String,
    connect_id: String,
    domains: Vec<String>,
    ca_cert: Vec<u8>,
    userid: String,
    uuid: String,
    services: Vec<String>,
}

#[repr(C)]
pub struct CRegistrationInfo {
    pub host: *const c_char,
    pub access_token: *const c_char,
    pub connect_id: *const c_char,
    pub domains: *const *const c_char,
    pub num_domains: c_int,
    pub ca_cert: *const c_char,
    pub num_cacert: c_int,
    pub userid: *const c_char,
    pub uuid: *const c_char,
    pub services: *const *const c_char,
    pub num_services: c_int,
}

#[derive(Default, Debug)]
#[repr(C)]
pub struct AgentStats {
    pub gateway_up: c_int,
    pub gateway_flaps: c_int,
    pub last_gateway_flap: c_int,
    pub gateway_flows: c_int,
    pub total_flows: c_int,
}

fn creginfo_translate(creg: CRegistrationInfo) -> RegistrationInfo {
    let mut reginfo = RegistrationInfo::default();
    unsafe {
        reginfo.host = CStr::from_ptr(creg.host).to_string_lossy().into_owned();
        reginfo.access_token = CStr::from_ptr(creg.access_token)
            .to_string_lossy()
            .into_owned();
        reginfo.connect_id = CStr::from_ptr(creg.connect_id)
            .to_string_lossy()
            .into_owned();
        reginfo.ca_cert = CStr::from_ptr(creg.ca_cert).to_bytes().to_owned();
        reginfo.userid = CStr::from_ptr(creg.userid).to_string_lossy().into_owned();
        reginfo.uuid = CStr::from_ptr(creg.uuid).to_string_lossy().into_owned();

        let tmp_array: &[c_char] = slice::from_raw_parts(creg.ca_cert, creg.num_cacert as usize);
        let rust_array: Vec<_> = tmp_array.iter().map(|&v| v as u8).collect();
        reginfo.ca_cert = rust_array;

        let tmp_array: &[*const c_char] =
            slice::from_raw_parts(creg.domains, creg.num_domains as usize);
        let rust_array: Vec<_> = tmp_array
            .iter()
            .map(|&v| CStr::from_ptr(v).to_string_lossy().into_owned())
            .collect();
        reginfo.domains = rust_array;

        let tmp_array: &[*const c_char] =
            slice::from_raw_parts(creg.services, creg.num_services as usize);
        let rust_array: Vec<_> = tmp_array
            .iter()
            .map(|&v| CStr::from_ptr(v).to_string_lossy().into_owned())
            .collect();
        reginfo.services = rust_array;
    }
    return reginfo;
}

struct FlowV4 {
    rx_socket: Box<dyn Transport>,
    rx_socket_idx: usize,
    rx_stream: Option<u64>,
    tx_stream: u64,
    tx_socket: usize,
    pending_tx: Option<NxtBufs>,
    pending_rx: VecDeque<NxtBufs>,
    creation_time: Instant,
    packet_age: usize,
    last_rdwr: Instant,
    cleanup_after: usize,
    dead: bool,
    pending_tx_qed: bool,
    service: String,
    parse_pending: Option<Vec<u8>>,
    dest_agent: String,
    active: bool,
}

enum TunFlow {
    NoFlow,
    OneToOne(FlowV4Key),
    OneToMany(HashMap<u64, FlowV4Key>),
}

struct Tun {
    tun: Box<dyn Transport>,
    pending_tx: VecDeque<FlowV4Key>,
    tx_ready: bool,
    flows: TunFlow,
    proxy_client: bool,
    pending_rx: usize,
}

impl Default for Tun {
    fn default() -> Self {
        Tun {
            tun: Box::new(Dummy::default()),
            pending_tx: VecDeque::with_capacity(0),
            tx_ready: true,
            flows: TunFlow::NoFlow,
            proxy_client: false,
            pending_rx: 0,
        }
    }
}

enum TunInfo {
    Tun(Tun),
    Flow(FlowV4Key),
}

impl TunInfo {
    fn tun(&mut self) -> &mut Tun {
        if let TunInfo::Tun(t) = self {
            t
        } else {
            panic!("Not a tun")
        }
    }
}

// To use the perf counters, just surround the code you want to measure with calls to
// perf_cnt.start() and perf_cnt.stop(), and that will use the x86 rdtsc() instruction
// set to measure rdtsc "ticks" consumed by the call. There is a utility "r2cnt" found
// here - https://github.com/gopakumarce/R2/tree/master/utils/r2cnt - this will dump the
// perf counters with three columns - first one is last rdtsc value which can be ignored,
// third one is the total rdtsc deltas accumulated and second one is the total number of
// times this perf_cnt was hit. Divide third column by second to get the average rdtsc
// delta count. More perf counters can be added to measure various points in code.
// This actually should be target-os linux AND target-arch x86_64, rdtsc is x86 only
#[cfg(target_os = "linux")]
struct AgentPerf {
    _counters: Counters,
    _perf_cnt: Perf,
}

#[cfg(target_os = "linux")]
fn alloc_perf() -> AgentPerf {
    // the r2cnt utility expects a counter name of r2cnt, this can be changed later to
    // pass in some name of our choice
    let mut _counters = Counters::new("r2cnt").unwrap();
    let _perf_cnt = Perf::new("perf_cnt1", &mut _counters);
    return AgentPerf {
        _counters,
        _perf_cnt,
    };
}

#[cfg(not(target_os = "linux"))]
struct AgentPerf {}

#[cfg(not(target_os = "linux"))]
fn alloc_perf() -> AgentPerf {
    AgentPerf {}
}

struct AgentInfo {
    idp_onboarded: bool,
    gw_onboarded: bool,
    platform: usize,
    reginfo: RegistrationInfo,
    vpn_fd: i32,
    vpn_tx: VecDeque<(usize, Vec<u8>)>,
    vpn_rx: VecDeque<(usize, Vec<u8>)>,
    flows: HashMap<FlowV4Key, FlowV4>,
    parse_pending: HashMap<FlowV4Key, ()>,
    tuns: HashMap<usize, TunInfo>,
    next_tun_idx: usize,
    vpn_tun: Tun,
    proxy_tun: Tun,
    reginfo_changed: usize,
    last_flap: Instant,
    rx_mtu: usize,
    tx_mtu: usize,
    _pktmem: usize,
    flows_active: HashMap<FlowV4Key, ()>,
    perf: AgentPerf,
}

impl Default for AgentInfo {
    fn default() -> Self {
        AgentInfo {
            idp_onboarded: false,
            gw_onboarded: false,
            platform: 0,
            reginfo: RegistrationInfo::default(),
            vpn_fd: 0,
            vpn_tx: VecDeque::new(),
            vpn_rx: VecDeque::new(),
            flows: HashMap::new(),
            parse_pending: HashMap::new(),
            tuns: HashMap::new(),
            next_tun_idx: TUN_START,
            vpn_tun: Tun::default(),
            proxy_tun: Tun::default(),
            reginfo_changed: 0,
            last_flap: Instant::now(),
            rx_mtu: 0,
            tx_mtu: 0,
            _pktmem: 0,
            flows_active: HashMap::new(),
            perf: alloc_perf(),
        }
    }
}

fn set_tx_socket(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    mut direct: bool,
    tuns: &mut HashMap<usize, TunInfo>,
    next_tun_idx: &mut usize,
    poll: &mut Poll,
    gw_onboarded: bool,
) {
    if DIRECT.load(std::sync::atomic::Ordering::Relaxed) == 1 {
        direct = true;
    }

    // TODO: let all dns go direct as of today, need a better dns story in future,
    // like for private domains how do we deal with dns ?
    if key.dport == 53 {
        direct = true;
    }

    let mut dummy = Tun::default();
    let tx_socket;
    let tx_stream;
    if direct {
        tx_socket = *next_tun_idx;
        let mut tun = NetConn::new_client(
            key.dip.to_string(),
            key.dport as usize,
            key.proto,
            true,
            None,
        );
        match tun.dial() {
            Err(_) => {
                flow_close(key, flow, Some(&mut dummy.tun), poll);
                return;
            }
            Ok(()) => {}
        }
        tx_stream = tun.new_stream();
        // The async tcp socket has to be established properly after handshake
        // and mio has to signal us that tx is ready before we can write. For
        // UDP tx is ready from get go
        let mut tx_ready = false;
        if key.proto == common::UDP {
            tx_ready = true;
        }
        *next_tun_idx = tx_socket + 1;
        let mut tun = Tun {
            tun: Box::new(tun),
            pending_tx: VecDeque::with_capacity(1),
            tx_ready,
            flows: TunFlow::OneToOne(key.clone()),
            proxy_client: false,
            pending_rx: 0,
        };
        match tun.tun.event_register(Token(tx_socket), poll, RegType::Reg) {
            Err(e) => {
                error!("Direct transport register failed {}", format!("{}", e));
                tun.tun.close(0).ok();
                flow_close(key, flow, Some(&mut tun.tun), poll);
                return;
            }
            Ok(_) => {}
        }
        tuns.insert(tx_socket, TunInfo::Tun(tun));
    } else if gw_onboarded {
        tx_socket = GWTUN_IDX;
        if let Some(gw_tun) = tuns.get_mut(&GWTUN_IDX) {
            let gw_tun = &mut gw_tun.tun();
            tx_stream = gw_tun.tun.new_stream();
            match gw_tun.flows {
                TunFlow::OneToMany(ref mut tun_flows) => {
                    tun_flows.insert(tx_stream, key.clone());
                }
                _ => panic!("We expect a hashmap for gateway flows"),
            }
        } else {
            flow_close(key, flow, Some(&mut dummy.tun), poll);
            return;
        }
    } else {
        // flow is supposed to go via nextensio, but nextensio gateway connection
        // is down at the moment, so close the flow
        flow_close(key, flow, Some(&mut dummy.tun), poll);
        return;
    }
    flow.tx_socket = tx_socket;
    flow.tx_stream = tx_stream;
}

fn flow_new(
    key: &FlowV4Key,
    need_parsing: bool,
    rx_socket_idx: Token,
    rx_socket: Box<dyn Transport>,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    parse_pending: &mut HashMap<FlowV4Key, ()>,
) {
    let cleanup_after;
    if key.proto == common::TCP {
        cleanup_after = CLEANUP_TCP_HALFOPEN;
    } else {
        cleanup_after = CLEANUP_UDP_IDLE;
    }

    // The flow tx socket / stream parameters will get overridden later when we
    // parse the flow's service and figure out if the flow is going direct or via
    // nextensio
    let f = FlowV4 {
        rx_socket,
        rx_socket_idx: rx_socket_idx.0,
        rx_stream: None,
        tx_stream: 0,
        tx_socket: UNUSED_IDX,
        pending_tx: None,
        pending_rx: VecDeque::with_capacity(1),
        packet_age: 0,
        last_rdwr: Instant::now(),
        creation_time: Instant::now(),
        cleanup_after,
        dead: false,
        pending_tx_qed: false,
        service: "".to_string(),
        dest_agent: "".to_string(),
        parse_pending: None,
        active: false,
    };
    if need_parsing {
        parse_pending.insert(key.clone(), ());
    }
    flows.insert(key.clone(), f);
}

// Today this dials websocket, in future with different possible transports,
// this can dial some other protocol, but eventually it returns a Transport trait
fn dial_gateway(reginfo: &RegistrationInfo) -> Option<WebSession> {
    let mut headers = HashMap::new();
    headers.insert(
        "x-nextensio-connect".to_string(),
        reginfo.connect_id.clone(),
    );
    let mut websocket =
        WebSession::new_client(reginfo.ca_cert.clone(), &reginfo.host, 443, headers, true);
    loop {
        match websocket.dial() {
            Err(e) => {
                error!("Dial gateway {} failed: {}", &reginfo.host, e.detail);
                STATS_NUMFLAPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                return None;
            }
            Ok(_) => {
                return Some(websocket);
            }
        }
    }
}

fn send_onboard_info(reginfo: &mut RegistrationInfo, tun: &mut Tun) -> bool {
    let mut onb = NxtOnboard::default();
    onb.agent = true;
    onb.userid = reginfo.userid.clone();
    onb.uuid = reginfo.uuid.clone();
    onb.services = reginfo.services.clone();
    onb.access_token = reginfo.access_token.clone();

    let mut hdr = NxtHdr::default();
    hdr.hdr = Some(Hdr::Onboard(onb));

    match tun.tun.write(
        0,
        NxtBufs {
            hdr: Some(hdr),
            bufs: vec![],
            headroom: 0,
        },
    ) {
        Err((_, e)) => match e.code {
            NxtErr::EWOULDBLOCK => {
                tun.tx_ready = false;
                false
            }
            _ => {
                error!("Onboard fail {}", e.detail);
                false
            }
        },
        Ok(_) => {
            error!("Onboard success");
            true
        }
    }
}

fn flow_rx_data(
    stream: u64,
    tun: &mut Tun,
    key: &FlowV4Key,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    mut data: NxtBufs,
    vpn_rx: &mut VecDeque<(usize, Vec<u8>)>,
    vpn_tx: &mut VecDeque<(usize, Vec<u8>)>,
    poll: &mut Poll,
) -> bool {
    if let Some(flow) = flows.get_mut(key) {
        if !flow.dead {
            if flow.rx_stream.is_none() && stream != flow.tx_stream {
                flow.rx_stream = Some(stream);
                match tun.flows {
                    TunFlow::OneToMany(ref mut tun_flows) => {
                        tun_flows.insert(stream, key.clone());
                    }
                    _ => {}
                }
            }
            // We dont need any nextensio headers at this point, so why waste memory
            // if this gets queued up for long ? Set it to None
            data.hdr = None;
            flow.pending_rx.push_back(data);
            tun.pending_rx += 1;
            flow_data_from_external(&key, flow, tun, poll);
            // this call will generate packets to be sent out back to the kernel
            // into the vpn_tx queue which will be processed in vpntun_tx
            flow.rx_socket.poll(vpn_rx, vpn_tx);
            return true;
        }
    }
    return false;
}

// Read in data coming in from gateway (or direct), find the corresponding flow
// and send the data to the flow. For data coming from the gateway, it comes with some
// inbuilt flow control mechanisms - we advertise how much data we can receive per flow
// to the gateway, so we wont have a situation of a flow having too much stuff backed up.
// But for direct flows if we find that our flow is getting backed up, we just stop reading
// from the direct socket anymore till the flow queue gets drained
fn external_sock_rx(
    max_pkts: usize,
    tun: &mut Tun,
    tun_idx: Token,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    vpn_rx: &mut VecDeque<(usize, Vec<u8>)>,
    vpn_tx: &mut VecDeque<(usize, Vec<u8>)>,
    poll: &mut Poll,
) {
    for _ in 0..max_pkts {
        if tun.pending_rx >= MAX_PENDING_RX {
            tun.tun.event_register(tun_idx, poll, RegType::Rereg).ok();
            return;
        }
        let ret = tun.tun.read();
        match ret {
            Err(x) => match x.code {
                NxtErr::EWOULDBLOCK => {
                    return;
                }
                _ => {
                    match tun.flows {
                        TunFlow::OneToOne(ref k) => {
                            if let Some(f) = flows.get_mut(k) {
                                tun.pending_rx -= flow_close(k, f, Some(&mut tun.tun), poll);
                            }
                        }
                        _ => {}
                    }
                    return;
                }
            },
            Ok((stream, data)) => {
                if let Some(hdr) = data.hdr.as_ref() {
                    // The stream close will only provide streamid, none of the other information will be valid
                    if hdr.streamop == StreamOp::Close as i32 {
                        match tun.flows {
                            TunFlow::OneToMany(ref mut tun_flows) => {
                                if let Some(k) = tun_flows.get(&hdr.streamid) {
                                    if let Some(f) = flows.get_mut(k) {
                                        tun.pending_rx -=
                                            flow_close(k, f, Some(&mut tun.tun), poll);
                                    }
                                }
                            }
                            _ => panic!("We expect hashmap for gateway flows"),
                        }
                    } else {
                        match hdr.hdr.as_ref().unwrap() {
                            Hdr::Onboard(onb) => {
                                assert_eq!(stream, 0);
                                error!(
                                    "Got onboard response, user {}, uuid {}",
                                    onb.userid, onb.uuid
                                );
                            }
                            Hdr::Flow(_) => {
                                let mut found = false;
                                if let Some(key) = hdr_to_key(&hdr) {
                                    found = flow_rx_data(
                                        stream, tun, &key, flows, data, vpn_rx, vpn_tx, poll,
                                    );
                                }
                                if !found {
                                    tun.tun.close(stream).ok();
                                }
                            }
                        }
                    }
                } else {
                    let key;
                    match tun.flows {
                        TunFlow::OneToOne(ref k) => {
                            key = k.clone();
                        }
                        _=> panic!("We either need an nxthdr to identify the flow or we need the tun to map 1:1 to the flow"),
                    }
                    let found = flow_rx_data(stream, tun, &key, flows, data, vpn_rx, vpn_tx, poll);
                    if !found {
                        tun.tun.close(stream).ok();
                    }
                }
            }
        }
    }
    // We read max_pkts and looks like we have more to read, yield and reregister
    tun.tun.event_register(tun_idx, poll, RegType::Rereg).ok();
}

fn external_sock_tx(
    tun: &mut Tun,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    reginfo: &RegistrationInfo,
    poll: &mut Poll,
    _perf: &mut AgentPerf,
) {
    tun.tx_ready = true;

    while let Some(key) = tun.pending_tx.pop_front() {
        if let Some(flow) = flows.get_mut(&key) {
            if !flow.dead {
                flow.pending_tx_qed = false;
                flow_data_to_external(&key, flow, tun, reginfo, poll, _perf);
                // If the flow is back to waiting state then we cant send any more
                // on this tunnel, so break out and try next time
                if flow.pending_tx.is_some() {
                    break;
                }
            }
        }
    }
    tun.pending_tx.shrink_to_fit();
}

fn set_dest_agent(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    reginfo: &RegistrationInfo,
    tuns: &mut HashMap<usize, TunInfo>,
    next_tun_idx: &mut usize,
    poll: &mut Poll,
    gw_onboarded: bool,
) {
    let mut found = false;
    let mut has_default = false;
    for d in reginfo.domains.iter() {
        if flow.service.contains(d) {
            flow.dest_agent = d.clone();
            found = true;
            break;
        }
        if !has_default && "nextensio-default-internet" == d {
            has_default = true;
        }
    }
    if !found {
        if has_default {
            flow.dest_agent = "nextensio-default-internet".to_string();
        }
    }
    set_tx_socket(
        key,
        flow,
        !found && !has_default,
        tuns,
        next_tun_idx,
        poll,
        gw_onboarded,
    );
}

fn parse_https_and_http(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    data: &[u8],
    reginfo: &RegistrationInfo,
    tuns: &mut HashMap<usize, TunInfo>,
    next_tun_idx: &mut usize,
    poll: &mut Poll,
    gw_onboarded: bool,
) -> bool {
    if let Some(service) = parse_sni(data) {
        flow.service = service;
        set_dest_agent(key, flow, reginfo, tuns, next_tun_idx, poll, gw_onboarded);
        return true;
    }
    let (_, _, service) = parse_host(data);
    if service != "" {
        flow.service = service;
        set_dest_agent(key, flow, reginfo, tuns, next_tun_idx, poll, gw_onboarded);
        return true;
    }

    return false;
}

// Add more data to the pending buffer and see if we can parse a service name
// with all that data. If we cant, keep waiting for more data. This flow will
// be sitting in a parse_pending hashmap which is monitored every 100ms and if
// it times out waiting for more data, we will just use the ip address as the
// service and send the flow across to the destination
fn parse_complete(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    mut tx: NxtBufs,
    reginfo: &RegistrationInfo,
    tuns: &mut HashMap<usize, TunInfo>,
    next_tun_idx: &mut usize,
    poll: &mut Poll,
    gw_onboarded: bool,
) -> Option<NxtBufs> {
    if let Some(mut pending) = flow.parse_pending.take() {
        for b in tx.bufs {
            pending.extend_from_slice(&b[tx.headroom..]);
            tx.headroom = 0;
        }
        if pending.len() >= PARSE_MAX {
            if !parse_https_and_http(
                key,
                flow,
                &pending[0..],
                reginfo,
                tuns,
                next_tun_idx,
                poll,
                gw_onboarded,
            ) {
                // We dont want any more data to parse, we give up and use dest ip as service
                flow.service = key.dip.clone();
                set_dest_agent(key, flow, reginfo, tuns, next_tun_idx, poll, gw_onboarded);
            }
            return Some(NxtBufs {
                hdr: tx.hdr,
                bufs: vec![pending],
                headroom: 0,
            });
        } else {
            // wait for more data or timeout
            flow.parse_pending = Some(pending);
            return None;
        }
    } else {
        // Most common case: the first buffer (usually at least 2048 in size) should be able
        // to contain a complete tls client hello (for https) or http headers with host
        // (for http). If the first buffer doesnt have the max data we want to attempt
        // to parse, then deep copy the buffers to one large buffer (very bad case ,( )
        if !tx.bufs.is_empty() {
            if parse_https_and_http(
                key,
                flow,
                &tx.bufs[0][tx.headroom..],
                reginfo,
                tuns,
                next_tun_idx,
                poll,
                gw_onboarded,
            ) {
                return Some(tx);
            } else {
                // We dont want any more data to parse, we give up and use dest ip as service
                if tx.bufs[0][tx.headroom..].len() >= PARSE_MAX {
                    flow.service = key.dip.clone();
                    set_dest_agent(key, flow, reginfo, tuns, next_tun_idx, poll, gw_onboarded);
                    return Some(tx);
                } else {
                    // We think more data will produce better parsing results, so wait for more data
                    let mut pending = Vec::with_capacity(common::get_maxbuf());
                    for b in tx.bufs {
                        pending.extend_from_slice(&b[tx.headroom..]);
                        tx.headroom = 0;
                    }
                    flow.parse_pending = Some(pending);
                    return None;
                }
            }
        }
    }
    return None;
}

// Now lets see if the smoltcp FSM deems that we have a payload to
// be read. Before that see if we had any payload pending to be processed
// and if so process it. The payload might be sent to the gateway or direct.
// NOTE: If we profile this api with the perf counters in AgentPerf, the
// tx_socket.tun.write is the most heavy call in here.
fn flow_data_to_external(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    tx_socket: &mut Tun,
    reginfo: &RegistrationInfo,
    poll: &mut Poll,
    _perf: &mut AgentPerf,
) {
    while tx_socket.tx_ready {
        let mut tx;
        if flow.pending_tx.is_some() {
            tx = flow.pending_tx.take().unwrap();
        } else {
            tx = match flow.rx_socket.read() {
                Ok((_, t)) => {
                    flow_alive(&key, flow);
                    t
                }
                Err(e) => match e.code {
                    NxtErr::EWOULDBLOCK => {
                        return;
                    }
                    _ => {
                        tx_socket.pending_rx -=
                            flow_close(key, flow, Some(&mut tx_socket.tun), poll);
                        return;
                    }
                },
            }
        }

        if flow.tx_socket == GWTUN_IDX {
            let mut hdr = key_to_hdr(key, &flow.service);
            hdr.streamid = flow.tx_stream;
            hdr.streamop = StreamOp::Noop as i32;
            match hdr.hdr.as_mut().unwrap() {
                Hdr::Flow(ref mut f) => {
                    f.source_agent = reginfo.connect_id.clone();
                    f.dest_agent = flow.dest_agent.clone()
                }
                _ => {}
            }
            tx.hdr = Some(hdr);
        }

        // Now try writing the payload to the destination socket. If the destination
        // socket says EWOULDBLOCK, then queue up the data as pending and try next time
        match tx_socket.tun.write(flow.tx_stream, tx) {
            Err((data, e)) => match e.code {
                NxtErr::EWOULDBLOCK => {
                    tx_socket.tx_ready = false;
                    if data.is_some() {
                        flow.pending_tx = data;
                        if !flow.pending_tx_qed {
                            // Well The tx socket is not ready, so queue ourselves
                            // upto be called when the tx socket becomes ready and
                            // get out of the loop.
                            tx_socket.pending_tx.push_back(key.clone());
                            flow.pending_tx_qed = true;
                        }
                    }
                    return;
                }
                _ => {
                    tx_socket.pending_rx -= flow_close(key, flow, Some(&mut tx_socket.tun), poll);
                    return;
                }
            },
            Ok(_) => {}
        }
    }
}

// Check if the flow has payload from the gateway (or direct) queued up in its
// pending_rx queue and if so try to give it to the tcp/udp stack and then if the
// stack spits that data out to be sent as packets to the app, do so by calling poll()
fn flow_data_from_external(key: &FlowV4Key, flow: &mut FlowV4, tun: &mut Tun, poll: &mut Poll) {
    while let Some(rx) = flow.pending_rx.pop_front() {
        match flow.rx_socket.write(0, rx) {
            Err((data, e)) => match e.code {
                NxtErr::EWOULDBLOCK => {
                    // The stack cant accept these pkts now, return the data to the head again
                    flow.pending_rx.push_front(data.unwrap());
                    return;
                }
                _ => {
                    tun.pending_rx -= flow_close(key, flow, Some(&mut tun.tun), poll);
                    return;
                }
            },
            Ok(_) => {
                tun.pending_rx -= 1;
                flow_alive(key, flow);
            }
        }
    }
    flow.pending_rx.shrink_to_fit();
}

// The proxy client starts off as a tcp socket (a TunInfo::Tun) at which point we have no idea
// about the "destination" of the socket. The destination becomes clear only after the client
// sends a CONNECT/GET request. Till that point the socket lingers in the TunInfo::Tun form.
// Once the client sends a CONNECT/GET, the read from the socket will return that info in a
// nextensio header (just one time), and then we figure the destination and create a flow and
// a destination socket etc.. and after that the tun/socket is associated with flow.rx_socket
// and then the tun dresses itself up as TunInfo::Flow for tunnel polling for its remaining life
fn proxyclient_rx(
    tun_info: TunInfo,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    parse_pending: &mut HashMap<FlowV4Key, ()>,
    tuns: &mut HashMap<usize, TunInfo>,
    tun_idx: Token,
    next_tun_idx: &mut usize,
    poll: &mut Poll,
    gw_onboarded: bool,
    reginfo: &RegistrationInfo,
    _perf: &mut AgentPerf,
) -> Option<TunInfo> {
    match tun_info {
        TunInfo::Tun(mut tun) => loop {
            let ret = tun.tun.read();
            match ret {
                Err(x) => match x.code {
                    NxtErr::EWOULDBLOCK => {
                        return Some(TunInfo::Tun(tun));
                    }
                    _ => {
                        tun.tun.event_register(tun_idx, poll, RegType::Dereg).ok();
                        tun.tun.close(0).ok();
                        return None;
                    }
                },
                Ok((_, data)) => {
                    if let Some(key) = hdr_to_key(data.hdr.as_ref().unwrap()) {
                        flow_new(&key, false, tun_idx, tun.tun, flows, parse_pending);
                        if let Some(flow) = flows.get_mut(&key) {
                            flow.service = key.dip.clone();
                            set_dest_agent(
                                &key,
                                flow,
                                reginfo,
                                tuns,
                                next_tun_idx,
                                poll,
                                gw_onboarded,
                            );
                            let tun_info = TunInfo::Flow(key.clone());
                            if let Some(tx_sock) = tuns.get_mut(&flow.tx_socket) {
                                if !flow.dead {
                                    // Send the data on to the destination
                                    flow.pending_tx = Some(data);
                                    flow_data_to_external(
                                        &key,
                                        flow,
                                        &mut tx_sock.tun(),
                                        reginfo,
                                        poll,
                                        _perf,
                                    );
                                    // trigger an immediate write back to the client by calling proxyclient_write().
                                    // the dummy data here is just to trigger a write. The immediate write might be
                                    // necessary if the client needs to receive an http-ok for example
                                    flow.pending_rx.push_back(NxtBufs {
                                        hdr: None,
                                        bufs: vec![vec![]],
                                        headroom: 0,
                                    });
                                    tx_sock.tun().pending_rx += 1;
                                    proxyclient_tx(&tun_info, flows, tuns, poll);
                                }
                            }
                            return Some(tun_info);
                        } else {
                            // Flow creation failed for whatever reason. The flow_new() will close and
                            // deregister etc.. if flow creation fails
                            return None;
                        }
                    } else {
                        // We have to get a key for the proxy client, otherwise its unusable
                        tun.tun.event_register(tun_idx, poll, RegType::Dereg).ok();
                        tun.tun.close(0).ok();
                        return None;
                    }
                }
            }
        },
        TunInfo::Flow(ref key) => {
            if let Some(flow) = flows.get_mut(&key) {
                if !flow.dead {
                    if let Some(tx_sock) = tuns.get_mut(&flow.tx_socket) {
                        flow_data_to_external(&key, flow, &mut tx_sock.tun(), reginfo, poll, _perf);
                    }
                    flow.rx_socket
                        .event_register(tun_idx, poll, RegType::Rereg)
                        .ok();
                }
            } else {
                panic!("Got an rx event for proxy client with no associated flow");
            }
            return Some(tun_info);
        }
    }
}

fn proxyclient_tx(
    tun_info: &TunInfo,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    tuns: &mut HashMap<usize, TunInfo>,
    poll: &mut Poll,
) {
    match tun_info {
        TunInfo::Flow(ref key) => {
            if let Some(flow) = flows.get_mut(&key) {
                if !flow.dead {
                    if let Some(tx_socket) = tuns.get_mut(&flow.tx_socket) {
                        flow_data_from_external(key, flow, &mut tx_socket.tun(), poll);
                    }
                }
            }
        }
        _ => { /* Not yet ready for tx, we havent received the connect request yet */ }
    }
}

// If the flow is fully parsed, return true. If the flow needs further parsing, return false
fn flow_parse(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    poll: &mut Poll,
    tuns: &mut HashMap<usize, TunInfo>,
    reginfo: &RegistrationInfo,
    next_tun_idx: &mut usize,
    gw_onboarded: bool,
) -> (bool, Option<NxtBufs>) {
    if flow.dead {
        // stop parsing any further
        return (true, None);
    }
    if flow.service != "" {
        // already parsed
        return (true, None);
    }

    loop {
        match flow.rx_socket.read() {
            Ok((_, tx)) => {
                flow_alive(&key, flow);
                if let Some(p) = parse_complete(
                    key,
                    flow,
                    tx,
                    reginfo,
                    tuns,
                    next_tun_idx,
                    poll,
                    gw_onboarded,
                ) {
                    // succesfully parsed
                    return (true, Some(p));
                } else {
                    // continue reading more data to try and complete the parse
                }
            }
            Err(e) => match e.code {
                NxtErr::EWOULDBLOCK => {
                    // Need more data to parse
                    return (false, None);
                }
                _ => {
                    if let Some(tx_socket) = tuns.get_mut(&flow.tx_socket) {
                        flow_close(key, flow, Some(&mut tx_socket.tun().tun), poll);
                    }
                    // errored, stop parsing any further
                    return (true, None);
                }
            },
        }
    }
}

// let the smoltcp/l3proxy stack process a packet from the kernel stack by running its FSM. The rx_socket.poll
// will read from the vpn_rx queue and potentially write data back to vpn_tx queue. vpn_rx and vpn_tx are just
// a set of global queues shared by all flows. Its easy to understand why vpn_tx is global since Tx from all
// flows have to go out of the same tun back to the kernel anyways. The reason vpn_rx is also global is because
// really nothing remains 'pending' in the vpn_rx queue after the poll below is called, the smoltcp stack will
// consume the pkt regardless of whether it could process it or not. So after the poll, the vpn_rx queue goes
// empty, so why have one queue per flow !
// NOTE1: At a later point if we have some other tcp/udp stack that does things differently, we can always have
// one rx queue per flow, its just saving some memory by having a global queue, thats about it
// NOTE2: Just read one packet, and process it and then send out a response if any triggered by that packet
// and then re-register for the next packet. This seems provide a more "cripsy" response to webpage
// loads than processing a bunch of rx packets together. That might also be because the smoltcp stack
// will just drop rx packets if they exceed the smoltcp rx buffer size, so if we try to do a bunch of
// rx packets, maybe that just translates into lost packets
fn vpntun_rx(
    max_pkts: usize,
    tun: &mut Tun,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    parse_pending: &mut HashMap<FlowV4Key, ()>,
    vpn_rx: &mut VecDeque<(usize, Vec<u8>)>,
    vpn_tx: &mut VecDeque<(usize, Vec<u8>)>,
    tuns: &mut HashMap<usize, TunInfo>,
    next_tun_idx: &mut usize,
    poll: &mut Poll,
    gw_onboarded: bool,
    reginfo: &RegistrationInfo,
    rx_mtu: usize,
    tx_mtu: usize,
    flows_active: &mut HashMap<FlowV4Key, ()>,
    _perf: &mut AgentPerf,
) {
    for _ in 0..max_pkts {
        let ret = tun.tun.read();
        match ret {
            Err(x) => match x.code {
                NxtErr::EWOULDBLOCK => {
                    return;
                }
                _ => {
                    // This will trigger monitor_vpnfd() to close and cleanup etc..
                    error!("VPN Tun Rx closed {}", x);
                    tun.tun.close(0).ok();
                    return;
                }
            },
            Ok((_, mut data)) => {
                for b in data.bufs {
                    if let Some(key) = decode_ipv4(&b[data.headroom..]) {
                        let mut f = flows.get_mut(&key);
                        if f.is_none() {
                            let rx_socket =
                                Box::new(Socket::new_client(&key, rx_mtu - NXT_OVERHEADS, tx_mtu));
                            flow_new(
                                &key,
                                true,
                                UNUSED_POLL, /* This socket is not registered with mio poller */
                                rx_socket,
                                flows,
                                parse_pending,
                            );
                            f = flows.get_mut(&key);
                        }
                        if let Some(flow) = f {
                            if !flow.active {
                                flows_active.insert(key.clone(), ());
                                flow.active = true;
                            }
                            // This is any kind of tcp/udp packet - payload or control - like it can be just
                            // a TCP ack. the socket.poll() below will figure all that out
                            vpn_rx.push_back((data.headroom, b));
                            // polling to handle the rx packet which is payload/control/both. Polling can also
                            // generate payload/control/both packets to be sent out back to the kernel into
                            // the vpn_tx queue and that will be processed in vpntun_tx.
                            // The payload if any in the rx packet will be available for "receiving" post poll,
                            // in the call to flow_data_to_external() below. Also a received packet like a tcp
                            // ACK might make more room for data from external queued up to be sent to the app
                            // so also attempt a flow_data_from_external call
                            flow.rx_socket.poll(vpn_rx, vpn_tx);
                            let (parsed, data) = flow_parse(
                                &key,
                                flow,
                                poll,
                                tuns,
                                reginfo,
                                next_tun_idx,
                                gw_onboarded,
                            );
                            if parsed && !flow.dead {
                                if data.is_some() {
                                    assert!(flow.pending_tx.is_none());
                                    flow.pending_tx = data;
                                }
                                if let Some(tx_sock) = tuns.get_mut(&flow.tx_socket) {
                                    flow_data_to_external(
                                        &key,
                                        flow,
                                        &mut tx_sock.tun(),
                                        reginfo,
                                        poll,
                                        _perf,
                                    );
                                    flow_data_from_external(&key, flow, &mut tx_sock.tun(), poll);
                                    // poll again to see if packets from external can be sent back to the flow/app via agent_tx
                                    flow.rx_socket.poll(vpn_rx, vpn_tx);
                                }
                            }
                        }
                    }
                    data.headroom = 0;
                }
            }
        }
    }
    // We read max_pkts and looks like we have more to read, yield and reregister
    tun.tun
        .event_register(VPNTUN_POLL, poll, RegType::Rereg)
        .ok();
}

fn vpntun_tx(tun: &mut Tun, vpn_tx: &mut VecDeque<(usize, Vec<u8>)>) {
    while let Some((headroom, tx)) = vpn_tx.pop_front() {
        let length = tx.len();
        match tun.tun.write(
            0,
            NxtBufs {
                hdr: None,
                bufs: vec![tx],
                headroom,
            },
        ) {
            Err((data, e)) => match e.code {
                NxtErr::EWOULDBLOCK => {
                    tun.tx_ready = false;
                    // Return the data to the head again
                    let mut data = data.unwrap();
                    vpn_tx.push_front((data.headroom, data.bufs.pop().unwrap()));
                    return;
                }
                _ => {
                    // This will trigger monitor_vpnfd() to close and cleanup etc..
                    error!("VPN TUN Tx closed {}, len {}", e, length);
                    tun.tun.close(0).ok();
                    return;
                }
            },
            Ok(_) => {}
        }
    }
    vpn_tx.shrink_to_fit();
}

fn new_gw(agent: &mut AgentInfo, poll: &mut Poll) {
    if !agent.idp_onboarded {
        return;
    }
    if let Some(websocket) = dial_gateway(&mut agent.reginfo) {
        let mut tun = Tun {
            tun: Box::new(websocket),
            pending_tx: VecDeque::with_capacity(1),
            tx_ready: false,
            flows: TunFlow::OneToMany(HashMap::new()),
            proxy_client: false,
            pending_rx: 0,
        };

        match tun.tun.event_register(GWTUN_POLL, poll, RegType::Reg) {
            Err(e) => {
                error!("Gateway transport register failed {}", format!("{}", e));
                tun.tun.close(0).ok();
                return;
            }
            Ok(_) => {
                error!("Gateway Transport Registered");
                agent.tuns.insert(GWTUN_IDX, TunInfo::Tun(tun));
            }
        }
    }
}

fn monitor_onboard(agent: &mut AgentInfo) {
    let cur_reginfo = REGINFO_CHANGED.load(std::sync::atomic::Ordering::Relaxed);
    if agent.reginfo_changed == cur_reginfo {
        return;
    }
    // If the onboarding changed, tear down the existing gateway tunnel
    if let Some(gw_tun) = agent.tuns.get_mut(&GWTUN_IDX) {
        // The gateway monitor will figure out that this is closed
        gw_tun.tun().tun.close(0).ok();
    }
    agent.reginfo_changed = cur_reginfo;
    unsafe { agent.reginfo = *REGINFO.take().unwrap() };
    agent.idp_onboarded = true;
}

fn monitor_gw(agent: &mut AgentInfo, poll: &mut Poll) {
    // If we want the agent to be in all-direct mode, dont bother about gateway
    if DIRECT.load(std::sync::atomic::Ordering::Relaxed) == 1 {
        return;
    }

    // Will be readded later down below
    let gw_tun_info = agent.tuns.remove(&GWTUN_IDX);
    if let Some(mut gw_tun_tun) = gw_tun_info {
        let gw_tun = &mut gw_tun_tun.tun();
        if gw_tun.tun.is_closed(0) {
            STATS_GWUP.store(0, std::sync::atomic::Ordering::Relaxed);
            STATS_NUMFLAPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            agent.last_flap = Instant::now();
            error!("Gateway transport closed, try opening again");
            agent.gw_onboarded = false;
            gw_tun
                .tun
                .event_register(GWTUN_POLL, poll, RegType::Dereg)
                .ok();
            close_gateway_flows(
                &mut agent.flows,
                &mut agent.parse_pending,
                &mut gw_tun_tun,
                &mut agent.tuns,
                poll,
                &mut agent.flows_active,
            );
            new_gw(agent, poll);
        } else {
            STATS_GWUP.store(1, std::sync::atomic::Ordering::Relaxed);
            match gw_tun.flows {
                TunFlow::OneToMany(ref mut tun_flows) => {
                    tun_flows.shrink_to_fit();
                    STATS_GWFLOWS
                        .store(tun_flows.len() as i32, std::sync::atomic::Ordering::Relaxed);
                }
                _ => {}
            }
            // Readded
            agent.tuns.insert(GWTUN_IDX, gw_tun_tun);
        }

        let now = Instant::now();
        if now > agent.last_flap {
            STATS_LASTFLAP.store(
                (now - agent.last_flap).as_secs() as i32,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
    } else {
        STATS_LASTFLAP.store(0, std::sync::atomic::Ordering::Relaxed);
        new_gw(agent, poll);
    }
}

fn app_transport(fd: i32, platform: usize) -> Box<dyn Transport> {
    let mut vpn_tun = Fd::new_client(fd, platform);
    match vpn_tun.dial() {
        Err(e) => {
            error!("app dial failed {}", e.detail);
        }
        _ => (),
    }
    Box::new(vpn_tun)
}

fn monitor_vpnfd(agent: &mut AgentInfo, poll: &mut Poll) {
    let fd = VPNFD.load(std::sync::atomic::Ordering::Relaxed);
    if agent.vpn_fd != 0 && (agent.vpn_fd != fd || agent.vpn_tun.tun.is_closed(0)) {
        error!(
            "App transport closed, try opening again {}/{}/{}",
            agent.vpn_fd,
            fd,
            agent.vpn_tun.tun.is_closed(0)
        );
        agent.vpn_tun.tun.close(0).ok();
        agent
            .vpn_tun
            .tun
            .event_register(VPNTUN_POLL, poll, RegType::Dereg)
            .ok();
        agent.vpn_fd = 0;

        // Will be readded down below
        let gw_tun_info = agent.tuns.remove(&GWTUN_IDX);
        if let Some(mut gw_tun) = gw_tun_info {
            close_gateway_flows(
                &mut agent.flows,
                &mut agent.parse_pending,
                &mut gw_tun,
                &mut agent.tuns,
                poll,
                &mut agent.flows_active,
            );
            agent.tuns.insert(GWTUN_IDX, gw_tun);
        }

        // After closing gateway flows, what is left is direct flows
        close_direct_flows(
            &mut agent.flows,
            &mut agent.parse_pending,
            &mut agent.tuns,
            poll,
            &mut agent.flows_active,
        );
    }
    if agent.vpn_fd != fd {
        let vpn_tun = app_transport(fd, agent.platform);
        let mut tun = Tun {
            tun: vpn_tun,
            pending_tx: VecDeque::with_capacity(1),
            tx_ready: true,
            flows: TunFlow::NoFlow,
            proxy_client: false,
            pending_rx: 0,
        };
        match tun.tun.event_register(VPNTUN_POLL, poll, RegType::Reg) {
            Err(e) => {
                error!("App transport register failed {}", format!("{}", e));
                agent.vpn_tun.tun.close(0).ok();
                agent.vpn_fd = 0;
                return;
            }
            _ => {
                error!("App Transport Registered {}/{}", agent.vpn_fd, fd);
                agent.vpn_tun = tun;
                agent.vpn_fd = fd;
                ()
            }
        }
    }
}

fn monitor_parse_pending(
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    parse_pending: &mut HashMap<FlowV4Key, ()>,
    tuns: &mut HashMap<usize, TunInfo>,
    reginfo: &mut RegistrationInfo,
    poll: &mut Poll,
    next_tun_idx: &mut usize,
    gw_onboarded: bool,
    _perf: &mut AgentPerf,
) {
    let mut keys = Vec::new();
    for (k, _) in parse_pending.iter_mut() {
        if let Some(f) = flows.get_mut(k) {
            if Instant::now() > f.creation_time + Duration::from_millis(SERVICE_PARSE_TIMEOUT) {
                // We couldnt parse the service, just use dest ip as service
                if f.service == "" {
                    f.service = k.dip.clone();
                    set_dest_agent(k, f, reginfo, tuns, next_tun_idx, poll, gw_onboarded);
                }
                if let Some(data) = f.parse_pending.take() {
                    if !f.dead {
                        // Send the data queued up for parsing immediately
                        f.pending_tx = Some(NxtBufs {
                            hdr: None,
                            bufs: vec![data],
                            headroom: 0,
                        });
                        if let Some(tx_sock) = tuns.get_mut(&f.tx_socket) {
                            flow_data_to_external(k, f, &mut tx_sock.tun(), reginfo, poll, _perf);
                        }
                    }
                }
                keys.push(k.clone());
            }
        }
    }
    for k in keys {
        parse_pending.remove(&k).unwrap();
    }
}

fn monitor_buffers(
    poll: &mut Poll,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    tuns: &mut HashMap<usize, TunInfo>,
    flows_active: &mut HashMap<FlowV4Key, ()>,
) {
    let mut keys = Vec::new();
    for (k, _) in flows_active.iter() {
        if let Some(mut f) = flows.get_mut(k) {
            f.packet_age += 1;
            // No packets the last 2 rounds (2secs)
            if f.packet_age >= 2 {
                // If the flow is still holding onto rx buffers, that means the rx buffers have
                // tcp holes which are not getting filled in 2 seconds, that has to mean some serious
                // trouble communicating with the OS kernel. Similarly, if it has tx buffers, that
                // means its not getting ACKs from the OS kernel. Close the flow.
                if !f.rx_socket.idle(false) || !f.pending_rx.is_empty() || f.pending_tx.is_some() {
                    error!(
                        "Buffer close flow {} / {}, idle {}, pending_rx {}, pending_tx {}",
                        k,
                        f.service,
                        f.rx_socket.idle(false),
                        f.pending_rx.len(),
                        f.parse_pending.is_some()
                    );
                    f.rx_socket.idle(true);
                    if let Some(tx_socket) = tuns.get_mut(&f.tx_socket) {
                        let tx_socket = tx_socket.tun();
                        tx_socket.pending_rx -= flow_close(k, f, Some(&mut tx_socket.tun), poll);
                    }
                }
                keys.push(k.clone());
            }
        }
    }
    for k in keys {
        flows_active.remove(&k);
    }
}

// Just punch the flow liveliness timestamp.
// The internet RFCs stipulate 4 hours for TCP idle flow, 5 minutes for UDP idle flow -
// we have made it some more shorter here, that will pbbly have to be bumped up to match
// the RFC eventually. And for dns we are being super aggressive here, cleaning up in 30 seconds.
fn flow_alive(key: &FlowV4Key, flow: &mut FlowV4) {
    // TODO: The last_rdwr can be gotten rid of and we can use the simple
    // packet_age counter to do the flow-aged determination too
    flow.last_rdwr = Instant::now();
    flow.packet_age = 0;
    if key.proto == common::TCP {
        flow.cleanup_after = CLEANUP_TCP_IDLE;
    } else {
        if key.dport == 53 {
            flow.cleanup_after = CLEANUP_UDP_DNS;
        } else {
            flow.cleanup_after = CLEANUP_UDP_IDLE;
        }
    }
}

// Send notifications to all parties (local kernel sockets, remote cluster etc..) that
// this flow is closed. ie generate a FIN/RST to local and direct sockets if the flow is
// direct,and send a message/signal to cluster if the flow is via nextensio. And then
// cleanup EVERYTHING THAT CONSUMES MEMORY **RIGHT AWAY**. And we let the flow hang around
// for a few more seconds to be cleaned up by monitor_flows - because even after we close
// the flow, we might get a few packets and we dont want to try and create new flow for
// those old packets etc..
fn flow_close(
    _key: &FlowV4Key,
    flow: &mut FlowV4,
    tx_socket: Option<&mut Box<dyn Transport>>,
    poll: &mut Poll,
) -> usize {
    // Tell all parties local and remote that the flow is closed
    if let Some(tx_socket) = tx_socket {
        // There maybe two streams - one going to external via tx socket and one coming
        // from external again via tx socket (forward and return). Close both
        tx_socket.close(flow.tx_stream).ok();
        if let Some(rx_stream) = flow.rx_stream {
            tx_socket.close(rx_stream).ok();
        }
        if flow.tx_socket != GWTUN_IDX && flow.tx_socket != UNUSED_IDX {
            tx_socket
                .event_register(Token(flow.tx_socket), poll, RegType::Dereg)
                .ok();
        }
    }
    flow.rx_socket.close(0).ok();
    // Unregister the poller so we dont keep polling till the flow is cleaned
    // up which can be many seconds away
    flow.rx_socket
        .event_register(Token(flow.rx_socket_idx), poll, RegType::Dereg)
        .ok();

    // Free all memory occupying stuff
    let pending = flow.pending_rx.len();
    flow.pending_rx.clear();
    flow.pending_tx = None;
    flow.parse_pending = None;
    flow.pending_tx_qed = false;
    flow.pending_tx = None;

    // Now let monitor_flows() clean up all other structures that has references/keys
    // to this flow and release the flow itself from flow table
    flow.dead = true;
    flow.cleanup_after = CLEANUP_NOW;

    return pending;
}

// Do all the close/cleanups etc.. and release the flow (ie remove from flow table)
fn flow_terminate(
    k: &FlowV4Key,
    f: &mut FlowV4,
    parse_pending: &mut HashMap<FlowV4Key, ()>,
    tx_sock_in: Option<&mut TunInfo>,
    tuns: &mut HashMap<usize, TunInfo>,
    flows_active: &mut HashMap<FlowV4Key, ()>,
    poll: &mut Poll,
) {
    let tx_sock;
    if tx_sock_in.is_some() {
        tx_sock = tx_sock_in;
    } else {
        tx_sock = tuns.get_mut(&f.tx_socket);
    }
    if let Some(tx_socket) = tx_sock {
        let tx_socket = tx_socket.tun();
        if !f.dead {
            tx_socket.pending_rx -= flow_close(k, f, Some(&mut tx_socket.tun), poll);
        }
        match tx_socket.flows {
            TunFlow::OneToMany(ref mut sock_flows) => {
                sock_flows.remove(&f.tx_stream);
                if let Some(rx_stream) = f.rx_stream {
                    sock_flows.remove(&rx_stream);
                }
            }
            _ => {}
        }
        if f.tx_socket != GWTUN_IDX && f.tx_socket != UNUSED_IDX {
            // Gateway socket is monitored seperately, if the flow is dead, just
            // deregister the tx socket if its a 1:1 (direct flow case) socket
            tuns.remove(&f.tx_socket);
        }
    } else {
        if !f.dead {
            flow_close(k, f, None, poll);
        }
    }
    tuns.remove(&f.rx_socket_idx);
    tuns.shrink_to_fit();
    parse_pending.remove(k);
    parse_pending.shrink_to_fit();
    flows_active.remove_entry(k);
    flows_active.shrink_to_fit();
}
// TODO: This can be made more effective by using some kind of timer wheel
// to sort the flows in the order of their expiry rather than having to walk
// through them all. Right now the use case is for a couple of hundred flows
// at most, so this might be just ok, but this needs fixing soon
fn monitor_flows(
    poll: &mut Poll,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    parse_pending: &mut HashMap<FlowV4Key, ()>,
    tuns: &mut HashMap<usize, TunInfo>,
    flows_active: &mut HashMap<FlowV4Key, ()>,
) {
    STATS_NUMFLOWS.store(flows.len() as i32, std::sync::atomic::Ordering::Relaxed);

    let mut keys = Vec::new();
    for (k, f) in flows.iter_mut() {
        let rdwr = f.last_rdwr + Duration::from_secs(f.cleanup_after as u64);
        let now = Instant::now();
        if now > rdwr {
            flow_terminate(k, f, parse_pending, None, tuns, flows_active, poll);
            keys.push(k.clone());
        }
    }
    for k in keys {
        flows.remove(&k);
    }
    flows.shrink_to_fit();
}

fn close_gateway_flows(
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    parse_pending: &mut HashMap<FlowV4Key, ()>,
    tun: &mut TunInfo,
    tuns: &mut HashMap<usize, TunInfo>,
    poll: &mut Poll,
    flows_active: &mut HashMap<FlowV4Key, ()>,
) {
    let mut keys = vec![];
    match tun.tun().flows {
        TunFlow::OneToMany(ref mut tun_flows) => {
            for (_, k) in tun_flows.iter() {
                keys.push(k.clone());
            }
            tun_flows.clear();
        }
        _ => panic!("Expecting hashmap for gateway tunnel"),
    }
    for k in keys {
        if let Some(f) = flows.get_mut(&k) {
            flow_terminate(&k, f, parse_pending, Some(tun), tuns, flows_active, poll);
            flows.remove(&k);
        }
    }
}

fn close_direct_flows(
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    parse_pending: &mut HashMap<FlowV4Key, ()>,
    tuns: &mut HashMap<usize, TunInfo>,
    poll: &mut Poll,
    flows_active: &mut HashMap<FlowV4Key, ()>,
) {
    let mut keys = Vec::new();
    for (k, f) in flows.iter_mut() {
        if f.tx_socket != GWTUN_IDX {
            flow_terminate(k, f, parse_pending, None, tuns, flows_active, poll);
            keys.push(k.clone());
        }
    }
    for k in keys {
        flows.remove(&k);
    }
}

fn proxy_listener(
    proxy: &mut Tun,
    tuns: &mut HashMap<usize, TunInfo>,
    next_tun_idx: &mut usize,
    poll: &mut Poll,
) {
    loop {
        match proxy.tun.listen() {
            Ok(client) => {
                let socket_idx = *next_tun_idx;
                *next_tun_idx = socket_idx + 1;
                let mut tun = Tun {
                    tun: client,
                    pending_tx: VecDeque::with_capacity(1),
                    tx_ready: true,
                    flows: TunFlow::NoFlow,
                    proxy_client: true,
                    pending_rx: 0,
                };
                match tun
                    .tun
                    .event_register(Token(socket_idx), poll, RegType::Reg)
                {
                    Err(e) => {
                        error!("Proxy transport register failed {}", format!("{}", e));
                        tun.tun.close(0).ok();
                        continue;
                    }
                    Ok(_) => {}
                }
                tuns.insert(socket_idx, TunInfo::Tun(tun));
            }
            Err(e) => match e.code {
                NxtErr::EWOULDBLOCK => {
                    return;
                }
                _ => {
                    error!("Proxy server error {}", e);
                    return;
                }
            },
        }
    }
}

fn proxy_init(agent: &mut AgentInfo, poll: &mut Poll) {
    agent.proxy_tun = Tun {
        tun: Box::new(WebProxy::new_client(NXT_AGENT_PROXY)),
        pending_tx: VecDeque::with_capacity(0),
        tx_ready: true,
        flows: TunFlow::NoFlow,
        proxy_client: false,
        pending_rx: 0,
    };
    agent.proxy_tun.tun.listen().ok();
    agent
        .proxy_tun
        .tun
        .event_register(WEBPROXY_POLL, poll, RegType::Reg)
        .ok();
}

fn agent_main_thread(platform: usize, direct: usize, rxmtu: usize, txmtu: usize, pktmem: usize) {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        Config::default()
            .with_min_level(Level::Info)
            .with_tag("NxtAgentLib"),
    );

    #[cfg(target_vendor = "apple")]
    OsLogger::new("com.nextensio.agent")
        .level_filter(LevelFilter::Debug)
        .init()
        .unwrap();

    error!("Agent init called");

    let mut poll = match Poll::new() {
        Err(e) => panic!("Cannot create a poller {:?}", e),
        Ok(p) => p,
    };
    let mut events = Events::with_capacity(2048);

    let mut agent = AgentInfo::default();
    if direct == 1 {
        DIRECT.store(1, std::sync::atomic::Ordering::Relaxed);
    }
    agent.platform = platform;
    // The mtu of the interface is set to the same as the buffer size, so we can READ packets as
    // large as the buffer size. But some platforms (like android) seems to perform poor when we
    // try to send packets closer to the interface mtu (mostly when mtu is large like 64K) and
    // hence we want to keep the txmtu  size different from the rxmtu. We control the size of the
    // tcp packets we receive to be rxmtu by doing mss-adjust when the tcp session is created
    agent.rx_mtu = rxmtu;
    agent.tx_mtu = txmtu;
    agent._pktmem = pktmem;
    agent.next_tun_idx = TUN_START;
    agent.tuns.insert(UNUSED_IDX, TunInfo::Tun(Tun::default()));
    common::set_maxbuf(rxmtu);

    proxy_init(&mut agent, &mut poll);

    let mut flow_ager = Instant::now();
    let mut service_parse_ager = Instant::now();
    let mut monitor_ager = Instant::now();
    let mut buffer_monitor = Instant::now();

    loop {
        let hundred_ms = Duration::from_millis(SERVICE_PARSE_TIMEOUT);
        match poll.poll(&mut events, Some(hundred_ms)) {
            Err(e) => error!("Error polling {:?}, retrying", e),
            Ok(_) => {}
        }

        for event in events.iter() {
            match event.token() {
                VPNTUN_POLL => {
                    if event.is_readable() {
                        vpntun_rx(
                            1,
                            &mut agent.vpn_tun,
                            &mut agent.flows,
                            &mut agent.parse_pending,
                            &mut agent.vpn_rx,
                            &mut agent.vpn_tx,
                            &mut agent.tuns,
                            &mut agent.next_tun_idx,
                            &mut poll,
                            agent.gw_onboarded,
                            &agent.reginfo,
                            agent.rx_mtu,
                            agent.tx_mtu,
                            &mut agent.flows_active,
                            &mut agent.perf,
                        );
                    }
                    if event.is_writable() {
                        agent.vpn_tun.tx_ready = true;
                    }
                }
                WEBPROXY_POLL => {
                    if event.is_readable() {
                        proxy_listener(
                            &mut agent.proxy_tun,
                            &mut agent.tuns,
                            &mut agent.next_tun_idx,
                            &mut poll,
                        )
                    }
                }
                idx => {
                    if let Some(mut tun_info) = agent.tuns.remove(&idx.0) {
                        let mut proxy = false;
                        match tun_info {
                            TunInfo::Tun(ref tun) => {
                                if tun.proxy_client {
                                    proxy = true;
                                }
                            }
                            TunInfo::Flow(_) => {
                                proxy = true;
                            }
                        }
                        if proxy {
                            if event.is_writable() {
                                proxyclient_tx(
                                    &tun_info,
                                    &mut agent.flows,
                                    &mut agent.tuns,
                                    &mut poll,
                                );
                            }
                            if event.is_readable() {
                                let rereg = proxyclient_rx(
                                    tun_info,
                                    &mut agent.flows,
                                    &mut agent.parse_pending,
                                    &mut agent.tuns,
                                    idx,
                                    &mut agent.next_tun_idx,
                                    &mut poll,
                                    agent.gw_onboarded,
                                    &agent.reginfo,
                                    &mut agent.perf,
                                );
                                if rereg.is_some() {
                                    agent.tuns.insert(idx.0, rereg.unwrap());
                                }
                            } else {
                                agent.tuns.insert(idx.0, tun_info);
                            }
                        } else {
                            if event.is_readable() {
                                external_sock_rx(
                                    1,
                                    &mut tun_info.tun(),
                                    idx,
                                    &mut agent.flows,
                                    &mut agent.vpn_rx,
                                    &mut agent.vpn_tx,
                                    &mut poll,
                                );
                            }
                            if event.is_writable() {
                                external_sock_tx(
                                    &mut tun_info.tun(),
                                    &mut agent.flows,
                                    &agent.reginfo,
                                    &mut poll,
                                    &mut agent.perf,
                                );
                            }
                            agent.tuns.insert(idx.0, tun_info);
                        }
                    }
                }
            }

            // Note that write-ready is a single shot event and it will continue to be write-ready
            // till we get an will-block return value on attempting some write. So as long as things
            // are write-ready, see if we have any pending data to Tx to the app tunnel or the gateway
            if agent.vpn_tun.tx_ready {
                vpntun_tx(&mut agent.vpn_tun, &mut agent.vpn_tx);
            }
        }

        if !agent.gw_onboarded && agent.idp_onboarded {
            if let Some(gw_tun) = agent.tuns.get_mut(&GWTUN_IDX) {
                agent.gw_onboarded = send_onboard_info(&mut agent.reginfo, &mut gw_tun.tun());
            }
        }

        // Note that we have a poll timeout of two seconds, but packets can keep the loop busy
        // so make sure we monitor only every two secs
        if Instant::now() > monitor_ager + Duration::from_secs(MONITOR_CONNECTIONS) {
            monitor_onboard(&mut agent);
            monitor_gw(&mut agent, &mut poll);
            monitor_vpnfd(&mut agent, &mut poll);
            monitor_ager = Instant::now();
        }
        if Instant::now() > service_parse_ager + Duration::from_millis(SERVICE_PARSE_TIMEOUT) {
            monitor_parse_pending(
                &mut agent.flows,
                &mut agent.parse_pending,
                &mut agent.tuns,
                &mut agent.reginfo,
                &mut poll,
                &mut agent.next_tun_idx,
                agent.gw_onboarded,
                &mut agent.perf,
            );
            service_parse_ager = Instant::now();
        }
        if Instant::now() > flow_ager + Duration::from_secs(MONITOR_FLOW_AGE) {
            // Check the flow aging only once every 30 seconds
            monitor_flows(
                &mut poll,
                &mut agent.flows,
                &mut agent.parse_pending,
                &mut agent.tuns,
                &mut agent.flows_active,
            );
            flow_ager = Instant::now();
        }
        if Instant::now() > buffer_monitor + Duration::from_secs(MONITOR_IDLE_BUFS) {
            monitor_buffers(
                &mut poll,
                &mut agent.flows,
                &mut agent.tuns,
                &mut agent.flows_active,
            );
            buffer_monitor = Instant::now();
        }
    }
}

// NOTE1: PLEASE ENSURE THAT THIS API IS CALLED ONLY ONCE BY THE PLATFORM
//
// NOTE2: This is a for-ever loop inside, so call this from a seperate thread in
// the platform (android/ios/linux/windows). We can launch a thread right in here
// and that works, but at least on android there is this problem of that thread
// mysteriously vanishing after a few hours, maybe its becuase the thread created
// here might not be the right priority etc.. ? The thread created from android
// itself seems to work fine and hence we are leaving the thread creation to the
// platform so it can choose the right priority etc..
#[no_mangle]
pub unsafe extern "C" fn agent_init(
    platform: usize,
    direct: usize,
    rxmtu: usize,
    txmtu: usize,
    pktmem: usize,
) {
    assert!(rxmtu >= txmtu);
    agent_main_thread(platform, direct, rxmtu, txmtu, pktmem);
}

// We EXPECT the fd provied to us to be already non blocking
#[no_mangle]
pub unsafe extern "C" fn agent_on(fd: i32) {
    let old_fd = VPNFD.load(std::sync::atomic::Ordering::Relaxed);
    error!("Agent on, old {}, new {}", old_fd, fd);
    VPNFD.store(fd, std::sync::atomic::Ordering::Relaxed);
}

#[no_mangle]
pub unsafe extern "C" fn agent_off() {
    let fd = VPNFD.load(std::sync::atomic::Ordering::Relaxed);
    error!("Agent off {}", fd);
    VPNFD.store(0, std::sync::atomic::Ordering::Relaxed);
}

#[no_mangle]
pub unsafe extern "C" fn onboard(info: CRegistrationInfo) {
    REGINFO = Some(Box::new(creginfo_translate(info)));
    REGINFO_CHANGED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

#[no_mangle]
pub unsafe extern "C" fn agent_stats(stats: *mut AgentStats) {
    (*stats).gateway_up = STATS_GWUP.load(std::sync::atomic::Ordering::Relaxed);
    (*stats).gateway_flaps = STATS_NUMFLAPS.load(std::sync::atomic::Ordering::Relaxed);
    (*stats).last_gateway_flap = STATS_LASTFLAP.load(std::sync::atomic::Ordering::Relaxed);
    (*stats).gateway_flows = STATS_GWFLOWS.load(std::sync::atomic::Ordering::Relaxed);
    (*stats).total_flows = STATS_NUMFLOWS.load(std::sync::atomic::Ordering::Relaxed);
}
