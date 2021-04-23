#[cfg(target_os = "android")]
use android_logger::Config;
use common::{
    decode_ipv4, hdr_to_key, key_to_hdr,
    nxthdr::{nxt_hdr::Hdr, nxt_hdr::StreamOp, NxtHdr, NxtOnboard},
    parse_host,
    tls::parse_sni,
    FlowV4Key, NxtBufs, NxtErr, RegType, Transport,
};
use dummy::Dummy;
use fd::Fd;
use l3proxy::Socket;
use log::{error, Level, LevelFilter};
use mio::{Events, Poll, Token};
use netconn::NetConn;
#[cfg(target_vendor = "apple")]
use oslog::OsLogger;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::slice;
use std::{collections::HashMap, time::Duration};
use std::{collections::VecDeque, time::Instant};
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

const CLEANUP_NOW: usize = 5; // 5 seconds
const CLEANUP_TCP_HALFOPEN: usize = 30; // 30 seconds
const CLEANUP_TCP_IDLE: usize = 60 * 60; // one hour
const CLEANUP_UDP_IDLE: usize = 4 * 60; // 4 minutes
const CLEANUP_UDP_DNS: usize = 30; // 30 seconds

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
    last_active: Instant,
    cleanup_after: usize,
    dead: bool,
    pending_tx_qed: bool,
    service: String,
    parse_pending: Option<Vec<u8>>,
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
}

impl Default for Tun {
    fn default() -> Self {
        Tun {
            tun: Box::new(Dummy::default()),
            pending_tx: VecDeque::with_capacity(0),
            tx_ready: true,
            flows: TunFlow::NoFlow,
            proxy_client: false,
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
        }
    }
}
// Mark when the flow should be cleaned up. The internet RFCs stipulate
// 4 hours for TCP idle flow, 5 minutes for UDP idle flow - we have made
// it some more shorter here, that will pbbly have to be bumped up to match
// the RFC eventually. As for terminated/FIN/RST flows, we clean that up
// after a short 5 second delay just so that new packets coming into the
// same tuple will not unnecessarily force us to create a socket again which
// will hang around in idle state for a long time. And for dns we are being
// super aggressive here, cleaning up in 30 seconds.
fn flow_alive(key: &FlowV4Key, flow: &mut FlowV4, alive: bool) {
    flow.last_active = Instant::now();
    if alive {
        if key.proto == common::TCP {
            flow.cleanup_after = CLEANUP_TCP_IDLE;
        } else {
            if key.dport == 53 {
                flow.cleanup_after = CLEANUP_UDP_DNS;
            } else {
                flow.cleanup_after = CLEANUP_UDP_IDLE;
            }
        }
    } else {
        flow.dead = true;
        flow.cleanup_after = CLEANUP_NOW;
        flow.pending_rx.clear();
        flow.pending_tx = None;
        flow.parse_pending = None;
    }
}

fn flow_close(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    tx_socket: &mut Box<dyn Transport>,
    poll: &mut Poll,
) {
    flow.rx_socket.close(0).ok();
    tx_socket.close(flow.tx_stream).ok();
    if let Some(rx_stream) = flow.rx_stream {
        tx_socket.close(rx_stream).ok();
    }
    flow_alive(key, flow, false);
    // Unregister the poller so we dont keep polling till the flow is cleaned
    // up which can be many seconds away
    flow.rx_socket
        .event_register(Token(flow.rx_socket_idx), poll, RegType::Dereg)
        .ok();
    if flow.tx_socket != GWTUN_IDX {
        tx_socket
            .event_register(Token(flow.tx_socket), poll, RegType::Dereg)
            .ok();
    }
}

fn flow_fail(mut rx_socket: Box<dyn Transport>, rx_socket_idx: Token, poll: &mut Poll) {
    rx_socket
        .event_register(rx_socket_idx, poll, RegType::Dereg)
        .ok();
    rx_socket.close(0).ok();
}

fn flow_new(
    key: &FlowV4Key,
    need_parsing: bool,
    rx_socket_idx: Token,
    rx_socket: Box<dyn Transport>,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    parse_pending: &mut HashMap<FlowV4Key, ()>,
    tuns: &mut HashMap<usize, TunInfo>,
    next_tun_idx: &mut usize,
    poll: &mut Poll,
    gw_onboarded: bool,
) {
    let mut direct = false;
    if DIRECT.load(std::sync::atomic::Ordering::Relaxed) == 1 {
        direct = true;
    }

    // TODO: let all dns go direct as of today, need a better dns story in future,
    // like for private domains how do we deal with dns ?
    if key.dport == 53 {
        direct = true;
    }

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
                flow_fail(rx_socket, rx_socket_idx, poll);
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
        };
        match tun.tun.event_register(Token(tx_socket), poll, RegType::Reg) {
            Err(e) => {
                error!("Direct transport register failed {}", format!("{}", e));
                tun.tun.close(0).ok();
                flow_fail(rx_socket, rx_socket_idx, poll);
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
            flow_fail(rx_socket, rx_socket_idx, poll);
            return;
        }
    } else {
        flow_fail(rx_socket, rx_socket_idx, poll);
        return;
    }

    let cleanup_after;
    if key.proto == common::TCP {
        cleanup_after = CLEANUP_TCP_HALFOPEN;
    } else {
        cleanup_after = CLEANUP_UDP_IDLE;
    }

    let f = FlowV4 {
        rx_socket,
        rx_socket_idx: rx_socket_idx.0,
        rx_stream: None,
        tx_stream,
        tx_socket,
        pending_tx: None,
        pending_rx: VecDeque::with_capacity(1),
        last_active: Instant::now(),
        creation_time: Instant::now(),
        cleanup_after,
        dead: false,
        pending_tx_qed: false,
        service: "".to_string(),
        parse_pending: None,
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
    tuns: &mut HashMap<usize, TunInfo>,
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
            flow_alive(&key, flow, true);
            flow_data_from_external(&key, flow, tuns, poll);
            // this call will generate packets to be sent out back to the kernel
            // into the vpn_tx queue which will be processed in vpntun_tx
            flow.rx_socket.poll(vpn_rx, vpn_tx);
            assert!(vpn_rx.len() == 0);
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
    tuns: &mut HashMap<usize, TunInfo>,
    vpn_rx: &mut VecDeque<(usize, Vec<u8>)>,
    vpn_tx: &mut VecDeque<(usize, Vec<u8>)>,
    poll: &mut Poll,
) {
    match tun.flows {
        TunFlow::OneToOne(ref k) => {
            // If its a 1:1 tunnel, and if we already have a backlog of data, then dont pull in more
            // If its a 1:many tunnel, we will send a flow control message back to the sender indicating
            // receive readiness, see api flow_rx_data(). Dont even bother reading a packet, just return
            if let Some(flow) = flows.get_mut(k) {
                if flow.pending_rx.len() > 1 {
                    // We read max_pkts and looks like we have more to read, yield and reregister
                    tun.tun.event_register(tun_idx, poll, RegType::Rereg).ok();
                    return;
                }
            }
        }
        _ => {}
    }
    for _ in 0..max_pkts {
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
                                flow_close(k, f, &mut tun.tun, poll);
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
                                        flow_close(k, f, &mut tun.tun, poll);
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
                                        stream, tun, &key, flows, tuns, data, vpn_rx, vpn_tx, poll,
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
                    let found =
                        flow_rx_data(stream, tun, &key, flows, tuns, data, vpn_rx, vpn_tx, poll);
                    if !found {
                        tun.tun.close(stream).ok();
                    }
                    // If its a 1:1 tunnel, and if we already have a backlog of data, then dont pull in more
                    // If its a 1:many tunnel, we will send a flow control message back to the sender indicating
                    // receive readiness, see api flow_rx_data()
                    if let Some(flow) = flows.get_mut(&key) {
                        if flow.pending_rx.len() > 1 {
                            // We read max_pkts and looks like we have more to read, yield and reregister
                            tun.tun.event_register(tun_idx, poll, RegType::Rereg).ok();
                            return;
                        }
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
) {
    tun.tx_ready = true;

    while let Some(key) = tun.pending_tx.pop_front() {
        if let Some(flow) = flows.get_mut(&key) {
            if !flow.dead {
                flow.pending_tx_qed = false;
                flow_data_to_external(&key, flow, tun, reginfo, poll);
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

fn parse_https_and_http(flow: &mut FlowV4, data: &[u8]) -> bool {
    if let Some(service) = parse_sni(data) {
        flow.service = service;
        return true;
    }
    let (_, _, service) = parse_host(data);
    if service != "" {
        flow.service = service;
        return true;
    }

    return false;
}
// Add more data to the pending buffer and see if we can parse a service name
// with all that data. If we cant, keep waiting for more data. This flow will
// be sitting in a parse_pending hashmap which is monitored every 100ms and if
// it times out waiting for more data, we will just use the ip address as the
// service and send the flow across to the destination
fn parse_complete(key: &FlowV4Key, flow: &mut FlowV4, mut tx: NxtBufs) -> Option<NxtBufs> {
    if let Some(mut pending) = flow.parse_pending.take() {
        for b in tx.bufs {
            pending.extend_from_slice(&b[tx.headroom..]);
            tx.headroom = 0;
        }
        if pending.len() >= common::MAXBUF {
            if !parse_https_and_http(flow, &pending[0..]) {
                // We dont want any more data to parse, we give up and use dest ip as service
                flow.service = key.dip.clone();
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
            if parse_https_and_http(flow, &tx.bufs[0][tx.headroom..]) {
                return Some(tx);
            } else {
                // We dont want any more data to parse, we give up and use dest ip as service
                if tx.bufs[0][tx.headroom..].len() >= common::MAXBUF {
                    flow.service = key.dip.clone();
                    return Some(tx);
                } else {
                    // We think more data will produce better parsing results, so wait for more data
                    let mut pending = Vec::with_capacity(common::MAXBUF);
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
fn flow_data_to_external(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    tx_socket: &mut Tun,
    reginfo: &RegistrationInfo,
    poll: &mut Poll,
) {
    flow_alive(&key, flow, true);
    while tx_socket.tx_ready {
        let mut tx;
        if flow.pending_tx.is_some() {
            tx = flow.pending_tx.take().unwrap();
        } else {
            tx = match flow.rx_socket.read() {
                Ok((_, t)) => t,
                Err(e) => match e.code {
                    NxtErr::EWOULDBLOCK => {
                        return;
                    }
                    _ => {
                        flow_close(key, flow, &mut tx_socket.tun, poll);
                        return;
                    }
                },
            }
        }
        if flow.service == "" {
            if let Some(p) = parse_complete(key, flow, tx) {
                tx = p;
            } else {
                // Read more data
                continue;
            }
        }

        if flow.tx_socket == GWTUN_IDX {
            let mut hdr = key_to_hdr(key);
            hdr.streamid = flow.tx_stream;
            hdr.streamop = StreamOp::Noop as i32;
            match hdr.hdr.as_mut().unwrap() {
                Hdr::Flow(ref mut f) => {
                    f.source_agent = reginfo.connect_id.clone();
                    f.origin_agent = reginfo.connect_id.clone();
                    let mut found = false;
                    for d in reginfo.domains.iter() {
                        if flow.service.contains(d) {
                            f.dest_agent = d.clone();
                            found = true;
                            break;
                        }
                    }
                    if !found {
                        f.dest_agent = "default-internet".to_string();
                    }
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
                    flow.pending_tx = Some(data.unwrap());
                    if !flow.pending_tx_qed {
                        // Well The tx socket is not ready, so queue ourselves
                        // upto be called when the tx socket becomes ready and
                        // get out of the loop.
                        tx_socket.pending_tx.push_back(key.clone());
                        flow.pending_tx_qed = true;
                    }
                    return;
                }
                _ => {
                    flow_close(key, flow, &mut tx_socket.tun, poll);
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
fn flow_data_from_external(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    tuns: &mut HashMap<usize, TunInfo>,
    poll: &mut Poll,
) {
    while let Some(rx) = flow.pending_rx.pop_front() {
        match flow.rx_socket.write(0, rx) {
            Err((data, e)) => match e.code {
                NxtErr::EWOULDBLOCK => {
                    // The stack cant accept these pkts now, return the data to the head again
                    flow.pending_rx.push_front(data.unwrap());
                    return;
                }
                _ => {
                    if let Some(tx_socket) = tuns.get_mut(&flow.tx_socket) {
                        flow_close(key, flow, &mut tx_socket.tun().tun, poll);
                    }
                    return;
                }
            },
            Ok(_) => {
                // See if the data we just gave the tcp/udp stack will be spit out
                // by the stack as packets to be sent in the vpn_tx queue
            }
        }
    }
    flow.pending_rx.shrink_to_fit();
    if flow.pending_rx.len() <= 1 {
        if flow.tx_socket == GWTUN_IDX {
            // TODO: Send a flow control message to flow.rx_stream signalling
            // the other end to send more data
        } else {
            if let Some(tx_socket) = tuns.get_mut(&flow.tx_socket) {
                tx_socket
                    .tun()
                    .tun
                    .event_register(Token(flow.tx_socket), poll, RegType::Rereg)
                    .ok();
            }
        }
    }
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
                        flow_new(
                            &key,
                            false,
                            tun_idx,
                            tun.tun,
                            flows,
                            parse_pending,
                            tuns,
                            next_tun_idx,
                            poll,
                            gw_onboarded,
                        );
                        if let Some(flow) = flows.get_mut(&key) {
                            flow.service = key.dip.clone();
                            if let Some(tx_sock) = tuns.get_mut(&flow.tx_socket) {
                                // Send the data on to the destination
                                flow.pending_tx = Some(data);
                                flow_data_to_external(
                                    &key,
                                    flow,
                                    &mut tx_sock.tun(),
                                    reginfo,
                                    poll,
                                );
                            }
                            // trigger an immediate write back to the client by calling proxyclient_write().
                            // the dummy data here is just to trigger a write. The immediate write might be
                            // necessary if the client needs to receive an http-ok for example
                            flow.pending_rx.push_back(NxtBufs {
                                hdr: None,
                                bufs: vec![vec![]],
                                headroom: 0,
                            });
                            let tun_info = TunInfo::Flow(key);
                            proxyclient_tx(&tun_info, flows, tuns, poll);
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
                        flow_data_to_external(&key, flow, &mut tx_sock.tun(), reginfo, poll);
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
                    flow_data_from_external(key, flow, tuns, poll);
                }
            }
        }
        _ => { /* Not yet ready for tx, we havent received the connect request yet */ }
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
                    tun.tun.close(0).ok();
                    return;
                }
            },
            Ok((_, mut data)) => {
                for b in data.bufs {
                    if let Some(key) = decode_ipv4(&b[data.headroom..]) {
                        let mut f = flows.get_mut(&key);
                        if f.is_none() {
                            let rx_socket = Box::new(Socket::new_client(&key, 1500));
                            flow_new(
                                &key,
                                true,
                                UNUSED_POLL, /* This socket is not registered with mio poller */
                                rx_socket,
                                flows,
                                parse_pending,
                                tuns,
                                next_tun_idx,
                                poll,
                                gw_onboarded,
                            );
                            f = flows.get_mut(&key);
                        }
                        if let Some(flow) = f {
                            if !flow.dead {
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
                                assert!(vpn_rx.len() == 0);
                                if let Some(tx_sock) = tuns.get_mut(&flow.tx_socket) {
                                    flow_data_to_external(
                                        &key,
                                        flow,
                                        &mut tx_sock.tun(),
                                        reginfo,
                                        poll,
                                    );
                                    flow_data_from_external(&key, flow, tuns, poll);
                                }
                                // poll again to see if packets from external can be sent back to the flow/app via agent_tx
                                flow.rx_socket.poll(vpn_rx, vpn_tx);
                                assert!(vpn_rx.len() == 0);
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

    if let Some(gw_tun) = agent.tuns.get_mut(&GWTUN_IDX) {
        let gw_tun = &mut gw_tun.tun();
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
            close_gateway_flows(&mut agent.flows, &mut agent.parse_pending, gw_tun, poll);
            agent.tuns.remove(&GWTUN_IDX);
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
        if let Some(gw_tun) = agent.tuns.get_mut(&GWTUN_IDX) {
            close_gateway_flows(
                &mut agent.flows,
                &mut agent.parse_pending,
                &mut gw_tun.tun(),
                poll,
            );
        }
        // After closing gateway flows, what is left is direct flows
        close_direct_flows(
            &mut agent.flows,
            &mut agent.parse_pending,
            &mut agent.tuns,
            poll,
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
) {
    let mut keys = Vec::new();
    for (k, _) in parse_pending.iter_mut() {
        if let Some(f) = flows.get_mut(k) {
            if Instant::now() > f.creation_time + Duration::from_millis(SERVICE_PARSE_TIMEOUT) {
                if let Some(data) = f.parse_pending.take() {
                    // We couldnt parse the service, just use dest ip as service
                    f.service = k.dip.clone();
                    // Send the data queued up for parsing immediately
                    f.pending_tx = Some(NxtBufs {
                        hdr: None,
                        bufs: vec![data],
                        headroom: 0,
                    });
                    if let Some(tx_sock) = tuns.get_mut(&f.tx_socket) {
                        if !f.dead {
                            flow_data_to_external(k, f, &mut tx_sock.tun(), reginfo, poll);
                        }
                    }
                }
                keys.push(k.clone());
            }
        } else {
            keys.push(k.clone());
        }
    }
    for k in keys {
        parse_pending.remove(&k).unwrap();
    }
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
) {
    STATS_NUMFLOWS.store(flows.len() as i32, std::sync::atomic::Ordering::Relaxed);

    let mut keys = Vec::new();
    for (k, f) in flows.iter_mut() {
        if Instant::now() > f.last_active + Duration::from_secs(f.cleanup_after as u64) {
            if let Some(tx_socket) = tuns.get_mut(&f.tx_socket) {
                let tx_socket = tx_socket.tun();
                flow_close(k, f, &mut tx_socket.tun, poll);
                match tx_socket.flows {
                    TunFlow::OneToMany(ref mut sock_flows) => {
                        sock_flows.remove(&f.tx_stream);
                        if let Some(rx_stream) = f.rx_stream {
                            sock_flows.remove(&rx_stream);
                        }
                    }
                    _ => {}
                }
                if f.pending_tx.is_some() {
                    // The flow key might be queued up in tx_socket.pending_tx, that will
                    // get removed in the next iteration of external_sock_tx()
                    f.pending_tx_qed = false;
                    f.pending_tx = None;
                }
                if f.tx_socket != GWTUN_IDX {
                    // Gateway socket is monitored seperately, if the flow is dead, just
                    // deregister the tx socket if its a 1:1 (direct flow case) socket
                    tx_socket
                        .tun
                        .event_register(Token(f.tx_socket), poll, RegType::Dereg)
                        .ok();
                    tuns.remove(&f.tx_socket);
                }
                f.rx_socket
                    .event_register(Token(f.rx_socket_idx), poll, RegType::Dereg)
                    .ok();
                tuns.remove(&f.rx_socket_idx);
            }
            f.pending_rx.clear();
            f.pending_tx = None;
            f.parse_pending = None;
            keys.push(k.clone());
        }
    }
    for k in keys {
        flows.remove(&k);
        if parse_pending.contains_key(&k) {
            parse_pending.remove(&k);
        }
    }
    flows.shrink_to_fit();
    tuns.shrink_to_fit();
}

fn close_gateway_flows(
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    parse_pending: &mut HashMap<FlowV4Key, ()>,
    tun: &mut Tun,
    poll: &mut Poll,
) {
    match tun.flows {
        TunFlow::OneToMany(ref mut tun_flows) => {
            for (_, k) in tun_flows.iter() {
                if let Some(f) = flows.get_mut(k) {
                    flow_close(k, f, &mut tun.tun, poll);
                    flows.remove(k);
                    if parse_pending.contains_key(k) {
                        parse_pending.remove(k);
                    }
                }
            }
            tun_flows.clear();
        }
        _ => panic!("Expecting hashmap for gateway tunnel"),
    }
}

fn close_direct_flows(
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    parse_pending: &mut HashMap<FlowV4Key, ()>,
    tuns: &mut HashMap<usize, TunInfo>,
    poll: &mut Poll,
) {
    let mut keys = Vec::new();
    for (k, f) in flows.iter_mut() {
        if f.tx_socket != GWTUN_IDX {
            if let Some(tun) = tuns.get_mut(&f.tx_socket) {
                flow_close(k, f, &mut tun.tun().tun, poll);
                tuns.remove(&f.tx_socket);
                keys.push(k.clone());
            }
        }
    }
    for k in keys {
        flows.remove(&k);
        if parse_pending.contains_key(&k) {
            parse_pending.remove(&k);
        }
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
    };
    agent.proxy_tun.tun.listen().ok();
    agent
        .proxy_tun
        .tun
        .event_register(WEBPROXY_POLL, poll, RegType::Reg)
        .ok();
}

fn agent_main_thread(platform: usize, direct: usize) {
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
    agent.next_tun_idx = TUN_START;

    proxy_init(&mut agent, &mut poll);

    let mut flow_ager = Instant::now();
    let mut service_parse_ager = Instant::now();
    let mut monitor_ager = Instant::now();
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
                            10, /* Read 10 packets and yield for other activities */
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
                                    10, /* Read 10 packets and yield for other activities */
                                    &mut tun_info.tun(),
                                    idx,
                                    &mut agent.flows,
                                    &mut agent.tuns,
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
        if Instant::now() > monitor_ager + Duration::from_secs(2) {
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
            );
            service_parse_ager = Instant::now();
        }
        if Instant::now() > flow_ager + Duration::from_secs(30) {
            // Check the flow aging only once every 30 seconds
            monitor_flows(
                &mut poll,
                &mut agent.flows,
                &mut agent.parse_pending,
                &mut agent.tuns,
            );
            flow_ager = Instant::now();
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
pub unsafe extern "C" fn agent_init(platform: usize, direct: usize) {
    agent_main_thread(platform, direct);
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
