#[cfg(target_os = "android")]
use android_logger::Config;
use common::{
    decode_ipv4, hdr_to_key, key_to_hdr,
    nxthdr::{nxt_hdr::Hdr, nxt_hdr::StreamOp, NxtFlow, NxtHdr, NxtOnboard},
    parse_host, pool_get,
    tls::parse_sni,
    FlowV4Key, NxtBufs,
    NxtErr::EWOULDBLOCK,
    NxtError, RegType, Transport,
};
#[cfg(target_os = "linux")]
use counters::Counters;
use dummy::Dummy;
use fd::Fd;
use l3proxy::Socket;
use log::{error, Level, LevelFilter};
use mio::{Events, Poll, Token};
use netconn::NetConn;
use object_pool::{Pool, Reusable};
#[cfg(target_vendor = "apple")]
use oslog::OsLogger;
#[cfg(target_os = "linux")]
use perf::Perf;
use std::net::Ipv4Addr;
use std::slice;
use std::sync::atomic::Ordering::Relaxed;
use std::thread;
use std::{collections::HashMap, time::Duration};
use std::{collections::VecDeque, time::Instant};
use std::{ffi::CStr, usize};
use std::{
    os::raw::{c_char, c_int},
    sync::Arc,
};
use std::{sync::atomic::AtomicI32, sync::atomic::AtomicU32, sync::atomic::AtomicUsize};
use webproxy::WebProxy;
use websock::WebSession;
mod dns;

// Note1: The "vpn" seen in this file refers to the tun interface from the OS on the device
// to our agent. Its bascailly the "vpnService" tunnel or the networkExtention/packetTunnel
// in ios.

// These are atomic because rust will complain loudly about mutable global variables
static VPNFD: AtomicI32 = AtomicI32::new(0);
static BINDIP: AtomicU32 = AtomicU32::new(0);
static DIRECT: AtomicI32 = AtomicI32::new(0);
static mut REGINFO: Option<Box<RegistrationInfo>> = None;
static REGINFO_CHANGED: AtomicUsize = AtomicUsize::new(0);

static STATS_GWUP: AtomicI32 = AtomicI32::new(0);
static STATS_NUMFLAPS: AtomicI32 = AtomicI32::new(0);
static STATS_LASTFLAP: AtomicI32 = AtomicI32::new(0);
static STATS_NUMFLOWS: AtomicI32 = AtomicI32::new(0);
static STATS_GWFLOWS: AtomicI32 = AtomicI32::new(0);
static AGENT_STARTED: AtomicUsize = AtomicUsize::new(0);
const NXT_AGENT_PROXY: usize = 8181;

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
const CLEANUP_UDP_DNS: usize = 10; // 10 seconds
const MONITOR_IDLE_BUFS: u64 = 1; // 1 seconds
const DNS_TTL: u32 = 300; // 5 minutes
const MONITOR_DNS: u64 = 360; // 6 minutes
const MONITOR_FLOW_AGE: u64 = 30; // 30 seconds
const MONITOR_CONNECTIONS: u64 = 2; // 2 seconds
const PARSE_MAX: usize = 2048;
const SERVICE_PARSE_TIMEOUT: u64 = 100; // milliseconds
const ONBOARD_RETRY: u64 = 500; // milliseconds
const MAXPAYLOAD: usize = 64 * 1024;
const MINPKTBUF: usize = 4096;
const MAX_PENDING_RX: usize = 4;
const FLOW_BUFFER_HOG: u64 = 4; // seconds;

#[derive(Default, Debug)]
pub struct Domain {
    pub name: String,
    needdns: bool,
    pub dnsip: u32,
}
#[derive(Default, Debug)]
pub struct RegistrationInfo {
    gateway: String,
    access_token: String,
    connect_id: String,
    cluster: String,
    domains: Vec<Domain>,
    ca_cert: Vec<u8>,
    userid: String,
    uuid: String,
    services: Vec<String>,
    hostname: String,
    model: String,
    os_type: String,
    os_name: String,
    os_patch: usize,
    os_major: usize,
    os_minor: usize,
    jaeger_collector: String,
    trace_users: String,
}

#[repr(C)]
pub struct CRegistrationInfo {
    pub gateway: *const c_char,
    pub access_token: *const c_char,
    pub connect_id: *const c_char,
    pub cluster: *const c_char,
    pub domains: *const *const c_char,
    pub needdns: *const c_int,
    pub dnsip: *const *const c_char,
    pub num_domains: c_int,
    pub ca_cert: *const c_char,
    pub num_cacert: c_int,
    pub userid: *const c_char,
    pub uuid: *const c_char,
    pub services: *const *const c_char,
    pub num_services: c_int,
    pub hostname: *const c_char,
    pub model: *const c_char,
    pub os_type: *const c_char,
    pub os_name: *const c_char,
    pub os_patch: c_int,
    pub os_major: c_int,
    pub os_minor: c_int,
    pub jaeger_collector: *const c_char,
    pub trace_users: *const c_char,
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
        reginfo.gateway = CStr::from_ptr(creg.gateway).to_string_lossy().into_owned();
        reginfo.access_token = CStr::from_ptr(creg.access_token)
            .to_string_lossy()
            .into_owned();
        reginfo.connect_id = CStr::from_ptr(creg.connect_id)
            .to_string_lossy()
            .into_owned();
        reginfo.cluster = CStr::from_ptr(creg.cluster).to_string_lossy().into_owned();
        reginfo.ca_cert = CStr::from_ptr(creg.ca_cert).to_bytes().to_owned();
        reginfo.userid = CStr::from_ptr(creg.userid).to_string_lossy().into_owned();
        reginfo.uuid = CStr::from_ptr(creg.uuid).to_string_lossy().into_owned();

        let tmp_array: &[c_char] = slice::from_raw_parts(creg.ca_cert, creg.num_cacert as usize);
        let rust_array: Vec<_> = tmp_array.iter().map(|&v| v as u8).collect();
        reginfo.ca_cert = rust_array;

        let tmp_array: &[*const c_char] =
            slice::from_raw_parts(creg.domains, creg.num_domains as usize);
        let domain_array: Vec<_> = tmp_array
            .iter()
            .map(|&v| CStr::from_ptr(v).to_string_lossy().into_owned())
            .collect();
        let tmp_array: &[c_int] = slice::from_raw_parts(creg.needdns, creg.num_domains as usize);
        let needdns_array: Vec<_> = tmp_array.iter().map(|&v| v).collect();
        let tmp_array: &[*const c_char] =
            slice::from_raw_parts(creg.dnsip, creg.num_domains as usize);
        let dnsip_array: Vec<_> = tmp_array
            .iter()
            .map(|&v| CStr::from_ptr(v).to_string_lossy().into_owned())
            .collect();
        reginfo.domains = Vec::new();
        for i in 0..creg.num_domains as usize {
            let ip: Result<Ipv4Addr, _> = dnsip_array[i].parse();
            if ip.is_ok() {
                let ip = ip.unwrap();
                let dnsip = common::as_u32_be(&ip.octets());
                let needdns = needdns_array[i] == 1;
                let d = Domain {
                    name: domain_array[i].clone(),
                    needdns,
                    dnsip,
                };
                reginfo.domains.push(d);
            } else {
                error!("Skipping bad ip address {}", &dnsip_array[i])
            }
        }
        // Longest name matches first
        reginfo
            .domains
            .sort_by(|a, b| b.name.chars().count().cmp(&a.name.chars().count()));

        let tmp_array: &[*const c_char] =
            slice::from_raw_parts(creg.services, creg.num_services as usize);
        let rust_array: Vec<_> = tmp_array
            .iter()
            .map(|&v| CStr::from_ptr(v).to_string_lossy().into_owned())
            .collect();
        reginfo.services = rust_array;

        reginfo.hostname = CStr::from_ptr(creg.hostname).to_string_lossy().into_owned();
        reginfo.model = CStr::from_ptr(creg.model).to_string_lossy().into_owned();
        reginfo.os_type = CStr::from_ptr(creg.os_type).to_string_lossy().into_owned();
        reginfo.os_name = CStr::from_ptr(creg.os_name).to_string_lossy().into_owned();
        reginfo.os_patch = creg.os_patch as usize;
        reginfo.os_major = creg.os_major as usize;
        reginfo.os_minor = creg.os_minor as usize;

        reginfo.jaeger_collector = CStr::from_ptr(creg.jaeger_collector)
            .to_string_lossy()
            .into_owned();
        reginfo.trace_users = CStr::from_ptr(creg.trace_users)
            .to_string_lossy()
            .into_owned();
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
    last_rdwr: Instant,
    cleanup_after: usize,
    dead: bool,
    pending_tx_qed: bool,
    service: String,
    parse_pending: Option<Reusable<Vec<u8>>>,
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

pub struct Dns {
    pub ip: Ipv4Addr,
    pub alloc_time: Instant,
}

pub struct Rdns {
    pub fqdn: String,
}

pub struct NameIP {
    pub start: Instant,
    pub dns: HashMap<String, Dns>,
    pub rdns: HashMap<Ipv4Addr, Rdns>,
}

struct AgentInfo {
    idp_onboarded: bool,
    gw_onboarded: bool,
    platform: usize,
    reginfo: RegistrationInfo,
    vpn_fd: i32,
    vpn_tx: VecDeque<(usize, Reusable<Vec<u8>>)>,
    vpn_rx: VecDeque<(usize, Reusable<Vec<u8>>)>,
    flows: HashMap<FlowV4Key, FlowV4>,
    parse_pending: HashMap<FlowV4Key, ()>,
    tuns: HashMap<usize, TunInfo>,
    next_tun_idx: usize,
    vpn_tun: Tun,
    proxy_tun: Tun,
    reginfo_changed: usize,
    last_flap: Instant,
    mtu: usize,
    flows_active: HashMap<FlowV4Key, ()>,
    check_tuns: HashMap<usize, ()>,
    npkts: usize,
    ntcp: usize,
    pkt_pool: Arc<Pool<Vec<u8>>>,
    tcp_pool: Arc<Pool<Vec<u8>>>,
    perf: AgentPerf,
    tcp_vpn: u32,
    tcp_vpn_handshake: Option<NxtBufs>,
    nameip: NameIP,
}

impl Default for AgentInfo {
    fn default() -> Self {
        let nameip = NameIP {
            start: Instant::now(),
            dns: HashMap::new(),
            rdns: HashMap::new(),
        };
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
            mtu: 0,
            flows_active: HashMap::new(),
            check_tuns: HashMap::new(),
            npkts: 0,
            ntcp: 0,
            pkt_pool: Arc::new(Pool::new(0, || Vec::with_capacity(0))),
            tcp_pool: Arc::new(Pool::new(0, || Vec::with_capacity(0))),
            perf: alloc_perf(),
            tcp_vpn: 0,
            tcp_vpn_handshake: None,
            nameip,
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
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    tcp_pool: &Arc<Pool<Vec<u8>>>,
) {
    if DIRECT.load(Relaxed) == 1 {
        direct = true;
    }

    // We dont want dns to be backhauled to nextensio clusters and add to
    // the delay in name resolution ! So let that go direct. This takes
    // care of plain dns and Dns over Tls (853). But Dns over HTTPs is
    // unfortunately just port 443 and we cant figure that out without adding
    // more logic about the destinatio IP also (well known dns servers)
    if key.dport == 53 || key.dport == 853 {
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
            pkt_pool.clone(),
            tcp_pool.clone(),
            BINDIP.load(Relaxed),
        );
        match tun.dial() {
            Err(_) => {
                flow_dead(key, flow);
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
                flow_dead(key, flow);
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
            flow_dead(key, flow);
            return;
        }
    } else {
        // flow is supposed to go via nextensio, but nextensio gateway connection
        // is down at the moment, so close the flow
        flow_dead(key, flow);
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
fn dial_gateway(
    reginfo: &RegistrationInfo,
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    tcp_pool: &Arc<Pool<Vec<u8>>>,
) -> Option<WebSession> {
    let mut headers = HashMap::new();
    headers.insert(
        "x-nextensio-connect".to_string(),
        reginfo.connect_id.clone(),
    );
    let mut websocket = WebSession::new_client(
        reginfo.ca_cert.clone(),
        &reginfo.gateway,
        443,
        headers,
        pkt_pool.clone(),
        tcp_pool.clone(),
        BINDIP.load(Relaxed),
    );
    match websocket.dial() {
        Err(e) => match e.code {
            EWOULDBLOCK => {
                return Some(websocket);
            }
            _ => {
                error!("Dial gateway {} failed: {}", &reginfo.gateway, e.detail);
                STATS_NUMFLAPS.fetch_add(1, Relaxed);
                return None;
            }
        },
        Ok(_) => {
            return Some(websocket);
        }
    }
}

fn extended_attributes(reginfo: &RegistrationInfo) -> String {
    // NOTE NOTE NOTE REMEMBER: There is no comma after the last element
    // in json. If the json format here is wrong then minion code will barf.
    // So to save some testing time, first print out this whole thing in a test
    // program and throw the json into an online json linter / validator and then
    // proceed to do rest of the testing
    return format!(
        r#"{{
        "_hostname": "{}", 
        "_model": "{}",
        "_osType": "{}",
        "_osName": "{}",
        "_osPatch": {},
        "_osMajor": {},
        "_osMinor": {}
    }}"#,
        reginfo.hostname.clone(),
        reginfo.model.clone(),
        reginfo.os_type.clone(),
        reginfo.os_name.clone(),
        reginfo.os_patch as u32,
        reginfo.os_major as u32,
        reginfo.os_minor as u32
    );
}

fn send_onboard_info(reginfo: &mut RegistrationInfo, tun: &mut Tun) {
    let mut onb = NxtOnboard::default();
    onb.agent = true;
    onb.userid = reginfo.userid.clone();
    onb.uuid = reginfo.uuid.clone();
    onb.services = reginfo.services.clone();
    onb.access_token = reginfo.access_token.clone();
    onb.cluster = reginfo.cluster.clone();
    onb.connect_id = reginfo.connect_id.clone();
    onb.attributes = extended_attributes(reginfo);

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
            EWOULDBLOCK => {
                tun.tx_ready = false;
                error!("Onboard message sent (block)");
            }
            _ => {
                error!("Onboard message send fail ({})", e.detail);
                tun.tun.close(0).ok();
            }
        },
        Ok(_) => {
            error!("Onboard message sent (ok)");
        }
    }
}

fn flow_rx_data(
    stream: u64,
    tun: &mut Tun,
    key: &FlowV4Key,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    mut data: NxtBufs,
    vpn_rx: &mut VecDeque<(usize, Reusable<Vec<u8>>)>,
    vpn_tx: &mut VecDeque<(usize, Reusable<Vec<u8>>)>,
    check_tuns: &mut HashMap<usize, ()>,
    flows_active: &mut HashMap<FlowV4Key, ()>,
) -> bool {
    if let Some(flow) = flows.get_mut(key) {
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
        flow_data_from_external(&key, flow, tun, check_tuns);
        // this call will generate packets to be sent out back to the kernel
        // into the vpn_tx queue which will be processed in vpntun_tx
        flow.rx_socket.poll(vpn_rx, vpn_tx);
        if !flow.active {
            flows_active.insert(key.clone(), ());
            flow.active = true;
        }
        return true;
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
    tun: &mut Tun,
    tun_idx: Token,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    vpn_rx: &mut VecDeque<(usize, Reusable<Vec<u8>>)>,
    vpn_tx: &mut VecDeque<(usize, Reusable<Vec<u8>>)>,
    poll: &mut Poll,
    check_tuns: &mut HashMap<usize, ()>,
    flows_active: &mut HashMap<FlowV4Key, ()>,
    gw_onboarded: &mut bool,
) {
    if tun.pending_rx >= MAX_PENDING_RX {
        tun.tun.event_register(tun_idx, poll, RegType::Rereg).ok();
        return;
    }
    let ret = tun.tun.read();
    match ret {
        Err(x) => match x.code {
            EWOULDBLOCK => {
                // It would appear as if we dont have to re-register if the socket says
                // it will block. But in case of websocket library, it keeps data buffered,
                // and returns EWOULDBLOCK *after* reading in all it can. So for such libs,
                // we have to reregister even if read returns EWOULDBLOCK
                tun.tun.event_register(tun_idx, poll, RegType::Rereg).ok();
                return;
            }
            _ => {
                let mut ck = FlowV4Key::default();
                match tun.flows {
                    TunFlow::OneToOne(ref k) => {
                        ck = k.clone();
                    }
                    _ => {}
                }
                if let Some(f) = flows.get_mut(&ck) {
                    flow_dead(&ck, f);
                }
                return;
            }
        },
        Ok((stream, data)) => {
            if let Some(hdr) = data.hdr.as_ref() {
                // The stream close will only provide streamid, none of the other information will be valid
                if hdr.streamop == StreamOp::Close as i32 {
                    let mut ck = FlowV4Key::default();
                    match tun.flows {
                        TunFlow::OneToMany(ref mut tun_flows) => {
                            if let Some(k) = tun_flows.get(&hdr.streamid) {
                                ck = k.clone();
                            }
                        }
                        _ => panic!("We expect hashmap for gateway flows"),
                    }
                    if let Some(f) = flows.get_mut(&ck) {
                        flow_dead(&ck, f);
                    }
                } else {
                    match hdr.hdr.as_ref().unwrap() {
                        Hdr::Onboard(onb) => {
                            assert_eq!(stream, 0);
                            error!(
                                "Got onboard response, user {}, uuid {}",
                                onb.userid, onb.uuid
                            );
                            *gw_onboarded = true;
                        }
                        Hdr::Flow(_) => {
                            let mut found = false;
                            if let Some(key) = hdr_to_key(&hdr) {
                                found = flow_rx_data(
                                    stream,
                                    tun,
                                    &key,
                                    flows,
                                    data,
                                    vpn_rx,
                                    vpn_tx,
                                    check_tuns,
                                    flows_active,
                                );
                            }
                            if !found {
                                tun.tun.close(stream).ok();
                            }
                        }
                        Hdr::Keepalive(_) => {}
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
                let found = flow_rx_data(
                    stream,
                    tun,
                    &key,
                    flows,
                    data,
                    vpn_rx,
                    vpn_tx,
                    check_tuns,
                    flows_active,
                );
                if !found {
                    tun.tun.close(stream).ok();
                }
            }
        }
    }
    tun.tun.event_register(tun_idx, poll, RegType::Rereg).ok();
}

fn external_sock_tx(
    tun: &mut Tun,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    reginfo: &RegistrationInfo,
    poll: &mut Poll,
    _perf: &mut AgentPerf,
    vpn_rx: &mut VecDeque<(usize, Reusable<Vec<u8>>)>,
    vpn_tx: &mut VecDeque<(usize, Reusable<Vec<u8>>)>,
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    nameip: &mut NameIP,
) {
    tun.tx_ready = true;

    while let Some(key) = tun.pending_tx.pop_front() {
        if let Some(flow) = flows.get_mut(&key) {
            flow.pending_tx_qed = false;
            flow.rx_socket.write_ready();
            flow.rx_socket.poll(vpn_rx, vpn_tx);
            flow_data_to_external(
                &key, flow, None, tun, reginfo, poll, pkt_pool, nameip, _perf,
            );
            // If the flow is back to waiting state then we cant send any more
            // on this tunnel, so break out and try next time
            if flow.pending_tx.is_some() {
                break;
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
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    tcp_pool: &Arc<Pool<Vec<u8>>>,
) {
    let mut found = false;
    let mut has_default = false;
    for d in reginfo.domains.iter() {
        if flow.service.contains(&d.name) {
            flow.dest_agent = d.name.clone();
            found = true;
            break;
        }
        if !has_default && "nextensio-default-internet" == d.name {
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
        pkt_pool,
        tcp_pool,
    );
}

fn parse_dns(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    reginfo: &RegistrationInfo,
    tuns: &mut HashMap<usize, TunInfo>,
    next_tun_idx: &mut usize,
    poll: &mut Poll,
    gw_onboarded: bool,
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    tcp_pool: &Arc<Pool<Vec<u8>>>,
    nameip: &mut NameIP,
) -> bool {
    // See if the flow's ip address matches any of the domains (reverse lookup)
    let ip: Result<Ipv4Addr, _> = key.dip.parse();
    if let Ok(ip) = ip {
        if let Some(r) = nameip.rdns.get(&ip) {
            flow.service = r.fqdn.clone();
            set_dest_agent(
                key,
                flow,
                reginfo,
                tuns,
                next_tun_idx,
                poll,
                gw_onboarded,
                pkt_pool,
                tcp_pool,
            );
            return true;
        }
    }
    return false;
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
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    tcp_pool: &Arc<Pool<Vec<u8>>>,
) -> bool {
    if let Some(service) = parse_sni(data) {
        flow.service = service;
        set_dest_agent(
            key,
            flow,
            reginfo,
            tuns,
            next_tun_idx,
            poll,
            gw_onboarded,
            pkt_pool,
            tcp_pool,
        );
        return true;
    }
    let (_, _, service) = parse_host(data);
    if service != "" {
        flow.service = service;
        set_dest_agent(
            key,
            flow,
            reginfo,
            tuns,
            next_tun_idx,
            poll,
            gw_onboarded,
            pkt_pool,
            tcp_pool,
        );
        return true;
    }

    return false;
}

fn parse_copy(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    pending: &mut Reusable<Vec<u8>>,
    mut tx: NxtBufs,
) -> (Vec<Reusable<Vec<u8>>>, Option<NxtHdr>) {
    let mut out = vec![];
    let max_copy = std::cmp::min(PARSE_MAX, pending.capacity());
    let mut remaining = max_copy - pending.len();
    let mut drain = 0;
    for b in tx.bufs.iter() {
        if remaining == 0 {
            break;
        }
        drain += 1;
        let l = b[tx.headroom..].len();
        if l > remaining {
            pending.extend_from_slice(&b[tx.headroom..tx.headroom + remaining]);
            // the first buffer in the chain is the pending buffer, and we dont allow
            // non-first buffers to have non-zero headroom, so we just copy it if thats
            // the case
            if let Some(mut new) = pool_get(pkt_pool.clone()) {
                // Clear just to set vector data/len to empty
                new.clear();
                new.extend_from_slice(&b[tx.headroom + remaining..]);
                out.push(new);
            } else {
                flow_dead(key, flow);
                return (out, None);
            }
            break;
        } else {
            pending.extend_from_slice(&b[tx.headroom..tx.headroom + l]);
            remaining -= l;
        }
        // Remember, only the first buffer in the chain has/may have headroom
        tx.headroom = 0;
    }
    tx.bufs.drain(0..drain);
    out.extend(tx.bufs);

    return (out, tx.hdr);
}

fn parse_or_maxlen(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    reginfo: &RegistrationInfo,
    tuns: &mut HashMap<usize, TunInfo>,
    next_tun_idx: &mut usize,
    poll: &mut Poll,
    gw_onboarded: bool,
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    tcp_pool: &Arc<Pool<Vec<u8>>>,
    nameip: &mut NameIP,
    buffer: &[u8],
) -> bool {
    // Easiest option: See if its an ip addresses we handed out and if so
    // we can reverse map the fqdn
    if parse_dns(
        key,
        flow,
        reginfo,
        tuns,
        next_tun_idx,
        poll,
        gw_onboarded,
        pkt_pool,
        tcp_pool,
        nameip,
    ) {
        return true;
    }

    // We dont yet have any clue how to parse udp / dtls
    if key.proto == common::UDP {
        flow.service = key.dip.clone();
        set_dest_agent(
            key,
            flow,
            reginfo,
            tuns,
            next_tun_idx,
            poll,
            gw_onboarded,
            pkt_pool,
            tcp_pool,
        );
        return true;
    }

    if parse_https_and_http(
        key,
        flow,
        buffer,
        reginfo,
        tuns,
        next_tun_idx,
        poll,
        gw_onboarded,
        pkt_pool,
        tcp_pool,
    ) {
        return true;
    } else if buffer.len() >= PARSE_MAX {
        // buffer has enough data and we still cant parse, set the service to
        // the destination IP and get out of here
        flow.service = key.dip.clone();
        set_dest_agent(
            key,
            flow,
            reginfo,
            tuns,
            next_tun_idx,
            poll,
            gw_onboarded,
            pkt_pool,
            tcp_pool,
        );
        return true;
    }
    return false;
}

fn parse_complete(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    tx: NxtBufs,
    reginfo: &RegistrationInfo,
    tuns: &mut HashMap<usize, TunInfo>,
    next_tun_idx: &mut usize,
    poll: &mut Poll,
    gw_onboarded: bool,
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    tcp_pool: &Arc<Pool<Vec<u8>>>,
    nameip: &mut NameIP,
) -> Option<NxtBufs> {
    if tx.bufs.is_empty() {
        return None;
    }
    // Most common case: the first buffer (usually at least 2048 in size) should be able
    // to contain a complete tls client hello (for https) or http headers with host
    // (for http). If the first buffer doesnt have the max data we want to attempt
    // to parse, then deep copy the buffers to one large buffer (very bad case ,( )
    if parse_or_maxlen(
        key,
        flow,
        reginfo,
        tuns,
        next_tun_idx,
        poll,
        gw_onboarded,
        pkt_pool,
        tcp_pool,
        nameip,
        &tx.bufs[0][tx.headroom..],
    ) {
        return Some(tx);
    }

    let mut pending;
    if flow.parse_pending.is_some() {
        pending = flow.parse_pending.take().unwrap();
    } else {
        if let Some(mut p) = pool_get(pkt_pool.clone()) {
            // Clear to set vector data/length to empty
            p.clear();
            pending = p;
        } else {
            flow_dead(key, flow);
            return None;
        }
    }
    let (out, hdr) = parse_copy(key, flow, pkt_pool, &mut pending, tx);
    if parse_or_maxlen(
        key,
        flow,
        reginfo,
        tuns,
        next_tun_idx,
        poll,
        gw_onboarded,
        pkt_pool,
        tcp_pool,
        nameip,
        &pending[0..],
    ) {
        let mut v = vec![pending];
        v.extend(out);
        return Some(NxtBufs {
            hdr: hdr,
            bufs: v,
            headroom: 0,
        });
    } else {
        // wait for more data or timeout
        flow.parse_pending = Some(pending);
        assert!(out.is_empty());
        return None;
    }
}

fn flow_handle_dns(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    reginfo: &RegistrationInfo,
    tx: &mut NxtBufs,
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    nameip: &mut NameIP,
) -> bool {
    // We can only handle plain un-encrypted dns requests as of
    // today. So for private domains, some device (like android)
    // sends us encrypted dns requests, we are hosed
    if key.dport != 53 || key.proto != common::UDP {
        return false;
    }
    if tx.bufs.len() == 0 {
        return false;
    }
    let mut req = dns::BytePacketBuffer::new(&mut tx.bufs[0][tx.headroom..]);
    if let Some(mut buf) = pool_get(pkt_pool.clone()) {
        let mut resp = dns::BytePacketBuffer::new(&mut buf[0..]);
        if dns::handle_nextensio_query(nameip, &reginfo.domains, &mut req, &mut resp) {
            let len = resp.pos();
            unsafe {
                buf.set_len(len);
            }
            match flow.rx_socket.write(
                0,
                NxtBufs {
                    hdr: None,
                    bufs: vec![buf],
                    headroom: 0,
                },
            ) {
                Err((_, e)) => match e.code {
                    // Dont care, dns will retry again
                    EWOULDBLOCK => {}
                    _ => flow_dead(key, flow),
                },
                Ok(_) => flow_alive(key, flow),
            }
            return true;
        }
    }
    return false;
}

// Now lets see if the smoltcp FSM deems that we have a payload to
// be read. Before that see if we had any payload pending to be processed
// and if so process it. The payload might be sent to the gateway or direct.
// NOTE: If we profile this api with the perf counters in AgentPerf, the
// tx_socket.tun.write is the most heavy call in here.
fn flow_data_to_external(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    mut init_data: Option<NxtBufs>,
    tx_socket: &mut Tun,
    reginfo: &RegistrationInfo,
    poll: &mut Poll,
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    nameip: &mut NameIP,
    _perf: &mut AgentPerf,
) {
    loop {
        let mut tx_init = true;
        let mut tx;
        if init_data.is_some() {
            tx = init_data.unwrap();
            init_data = None;
        } else if flow.pending_tx.is_some() {
            tx = flow.pending_tx.take().unwrap();
            // Something is queued up because it couldnt be sent last time, DONT
            // muck around with it, send it EXACTLY as it is to the tx socket.
            tx_init = false;
        } else {
            tx = match flow.rx_socket.read() {
                Ok((_, t)) => {
                    flow_alive(&key, flow);
                    t
                }
                Err(e) => match e.code {
                    EWOULDBLOCK => {
                        return;
                    }
                    _ => {
                        flow_dead(key, flow);
                        return;
                    }
                },
            }
        }

        if flow.tx_socket == GWTUN_IDX && tx_init {
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

        // See if its a dns query for a private domain that we can respond to
        let ret;
        if flow_handle_dns(key, flow, reginfo, &mut tx, pkt_pool, nameip) {
            // flow_rx_tx which called us will call flow_data_from_external and send
            // the dns response to vpn_tx
            ret = Ok(());
        } else {
            // Now try writing the payload to the destination socket. If the destination
            // socket says EWOULDBLOCK, then queue up the data as pending and try next time
            if !tx_socket.tx_ready {
                ret = Err((
                    Some(tx),
                    NxtError {
                        code: EWOULDBLOCK,
                        detail: "".to_string(),
                    },
                ))
            } else {
                ret = tx_socket.tun.write(flow.tx_stream, tx);
            }
        }
        match ret {
            Err((data, e)) => match e.code {
                EWOULDBLOCK => {
                    tx_socket.tx_ready = false;
                    if !tx_socket.tx_ready {
                        tx_socket
                            .tun
                            .event_register(Token(flow.tx_socket), poll, RegType::Rereg)
                            .ok();
                    }
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
                    flow_dead(key, flow);
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
    tun: &mut Tun,
    check_tuns: &mut HashMap<usize, ()>,
) {
    while let Some(rx) = flow.pending_rx.pop_front() {
        tun.pending_rx -= 1;
        match flow.rx_socket.write(0, rx) {
            Err((data, e)) => match e.code {
                EWOULDBLOCK => {
                    // The stack cant accept these pkts now, return the data to the head again
                    flow.pending_rx.push_front(data.unwrap());
                    tun.pending_rx += 1;
                    return;
                }
                _ => {
                    flow_dead(key, flow);
                    return;
                }
            },
            Ok(_) => {
                if tun.pending_rx < MAX_PENDING_RX {
                    if !check_tuns.contains_key(&flow.tx_socket) {
                        check_tuns.insert(flow.tx_socket, ());
                    }
                }
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
    check_tuns: &mut HashMap<usize, ()>,
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    tcp_pool: &Arc<Pool<Vec<u8>>>,
    nameip: &mut NameIP,
    _perf: &mut AgentPerf,
) -> Option<TunInfo> {
    match tun_info {
        TunInfo::Tun(mut tun) => loop {
            let ret = tun.tun.read();
            match ret {
                Err(x) => match x.code {
                    EWOULDBLOCK => {
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
                                pkt_pool,
                                tcp_pool,
                            );
                            let tun_info = TunInfo::Flow(key.clone());
                            if let Some(tx_sock) = tuns.get_mut(&flow.tx_socket) {
                                flow_data_to_external(
                                    &key,
                                    flow,
                                    Some(data),
                                    &mut tx_sock.tun(),
                                    reginfo,
                                    poll,
                                    pkt_pool,
                                    nameip,
                                    _perf,
                                );
                                if let Some(mut empty) = pool_get(pkt_pool.clone()) {
                                    // Clear to just set vector data/length to be empty
                                    empty.clear();
                                    // trigger an immediate write back to the client by calling proxyclient_write().
                                    // the dummy data here is just to trigger a write. The immediate write might be
                                    // necessary if the client needs to receive an http-ok for example
                                    flow.pending_rx.push_back(NxtBufs {
                                        hdr: None,
                                        bufs: vec![empty],
                                        headroom: 0,
                                    });
                                    tx_sock.tun().pending_rx += 1;
                                    proxyclient_tx(&tun_info, flows, tuns, check_tuns);
                                } else {
                                    flow_dead(&key, flow);
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
                if let Some(tx_sock) = tuns.get_mut(&flow.tx_socket) {
                    flow_data_to_external(
                        &key,
                        flow,
                        None,
                        &mut tx_sock.tun(),
                        reginfo,
                        poll,
                        pkt_pool,
                        nameip,
                        _perf,
                    );
                }
                flow.rx_socket
                    .event_register(tun_idx, poll, RegType::Rereg)
                    .ok();
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
    check_tuns: &mut HashMap<usize, ()>,
) {
    match tun_info {
        TunInfo::Flow(ref key) => {
            if let Some(flow) = flows.get_mut(&key) {
                if let Some(tx_socket) = tuns.get_mut(&flow.tx_socket) {
                    flow_data_from_external(key, flow, &mut tx_socket.tun(), check_tuns);
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
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    tcp_pool: &Arc<Pool<Vec<u8>>>,
    nameip: &mut NameIP,
) -> (bool, Option<NxtBufs>) {
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
                    pkt_pool,
                    tcp_pool,
                    nameip,
                ) {
                    // succesfully parsed
                    return (true, Some(p));
                } else {
                    // continue reading more data to try and complete the parse
                }
            }
            Err(e) => match e.code {
                EWOULDBLOCK => {
                    // Need more data to parse
                    return (false, None);
                }
                _ => {
                    flow_dead(key, flow);
                    // errored, stop parsing any further
                    return (true, None);
                }
            },
        }
    }
}

fn flow_rx_tx(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    init_data: Option<NxtBufs>,
    vpn_rx: &mut VecDeque<(usize, Reusable<Vec<u8>>)>,
    vpn_tx: &mut VecDeque<(usize, Reusable<Vec<u8>>)>,
    tuns: &mut HashMap<usize, TunInfo>,
    poll: &mut Poll,
    reginfo: &RegistrationInfo,
    check_tuns: &mut HashMap<usize, ()>,
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    nameip: &mut NameIP,
    _perf: &mut AgentPerf,
) {
    if let Some(tx_sock) = tuns.get_mut(&flow.tx_socket) {
        flow_data_to_external(
            &key,
            flow,
            init_data,
            &mut tx_sock.tun(),
            reginfo,
            poll,
            pkt_pool,
            nameip,
            _perf,
        );
        flow_data_from_external(&key, flow, &mut tx_sock.tun(), check_tuns);
        if !flow.pending_tx.is_some() {
            flow.rx_socket.write_ready();
        }
        // poll again to see if packets from external can be sent back to the flow/app via agent_tx
        flow.rx_socket.poll(vpn_rx, vpn_tx);
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
// NOTE2: We read a packet, put it into vpn_rx, give it to smoltcp by calling rx_socket.poll() - and we repeat
// that a bunch of times. Lets say we do that 10 times and 8 times the packets are all for the same tcp flow,
// which will help collect a bunch of a tcp data for that flow - and maybe the rest two are for another tcp
// flow or maybe two seperate udp flows. Once all tcp flow packets are given to smoltcp, at the very end we
// call flow_rx_tx to basically take that data and send it to external and read from external etc.. - this
// helps in achieve better tcp upstream performance. As can be seen here we dont do that for udp, because there
// is really no concept of "stream / collecting-data" for udp, so we  process each packet / each bit of udp data
// as and when it arrives as a packet from the vpn tunnel
fn vpntun_rx(
    max_pkts: usize,
    tun: &mut Tun,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    parse_pending: &mut HashMap<FlowV4Key, ()>,
    vpn_rx: &mut VecDeque<(usize, Reusable<Vec<u8>>)>,
    vpn_tx: &mut VecDeque<(usize, Reusable<Vec<u8>>)>,
    tuns: &mut HashMap<usize, TunInfo>,
    next_tun_idx: &mut usize,
    poll: &mut Poll,
    gw_onboarded: bool,
    reginfo: &RegistrationInfo,
    mtu: usize,
    flows_active: &mut HashMap<FlowV4Key, ()>,
    check_tuns: &mut HashMap<usize, ()>,
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    tcp_pool: &Arc<Pool<Vec<u8>>>,
    nameip: &mut NameIP,
    _perf: &mut AgentPerf,
) {
    let mut tcp_flows = HashMap::new();
    for _ in 0..max_pkts {
        let ret = tun.tun.read();
        match ret {
            Err(x) => match x.code {
                EWOULDBLOCK => {
                    for (key, data) in tcp_flows {
                        if let Some(flow) = flows.get_mut(&key) {
                            flow_rx_tx(
                                &key, flow, data, vpn_rx, vpn_tx, tuns, poll, reginfo, check_tuns,
                                pkt_pool, nameip, _perf,
                            );
                        }
                    }
                    tun.tun
                        .event_register(Token(VPNTUN_IDX), poll, RegType::Rereg)
                        .ok();
                    return;
                }
                _ => {
                    // This will trigger monitor_fd_vpn() to close and cleanup etc..
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
                            if let Some(rx_socket) =
                                Socket::new_client(&key, mtu, pkt_pool.clone(), tcp_pool.clone())
                            {
                                flow_new(
                                    &key,
                                    true,
                                    UNUSED_POLL, /* This socket is not registered with mio poller */
                                    Box::new(rx_socket),
                                    flows,
                                    parse_pending,
                                );
                            }
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
                                pkt_pool,
                                tcp_pool,
                                nameip,
                            );
                            if parsed {
                                if key.proto != common::TCP {
                                    flow_rx_tx(
                                        &key, flow, data, vpn_rx, vpn_tx, tuns, poll, reginfo,
                                        check_tuns, pkt_pool, nameip, _perf,
                                    );
                                } else {
                                    if !tcp_flows.contains_key(&key) {
                                        tcp_flows.insert(key, data);
                                    }
                                }
                            }
                        }
                    }
                    data.headroom = 0;
                }
            }
        }
    }
    for (key, data) in tcp_flows {
        if let Some(flow) = flows.get_mut(&key) {
            flow_rx_tx(
                &key, flow, data, vpn_rx, vpn_tx, tuns, poll, reginfo, check_tuns, pkt_pool,
                nameip, _perf,
            );
        }
    }
    // We read max_pkts and looks like we have more to read, yield and reregister
    tun.tun
        .event_register(VPNTUN_POLL, poll, RegType::Rereg)
        .ok();
}

fn vpntun_tx(tun: &mut Tun, vpn_tx: &mut VecDeque<(usize, Reusable<Vec<u8>>)>, poll: &mut Poll) {
    while let Some((headroom, tx)) = vpn_tx.pop_front() {
        let length = tx.len() - headroom;
        // The vpn tun can be of type tcp also, in which case we need just a default header,
        // to have proper framing over tcp
        let mut hdr = NxtHdr::default();
        let flow = NxtFlow::default();
        hdr.hdr = Some(Hdr::Flow(flow));
        match tun.tun.write(
            0,
            NxtBufs {
                hdr: Some(hdr),
                bufs: vec![tx],
                headroom,
            },
        ) {
            Err((data, e)) => match e.code {
                EWOULDBLOCK => {
                    tun.tx_ready = false;
                    if data.is_some() {
                        // Return the data to the head again
                        let mut data = data.unwrap();
                        if data.bufs.len() != 0 {
                            vpn_tx.push_front((data.headroom, data.bufs.pop().unwrap()));
                        }
                    }
                    tun.tun
                        .event_register(Token(VPNTUN_IDX), poll, RegType::Rereg)
                        .ok();
                    return;
                }
                _ => {
                    // This will trigger monitor_fd_vpn() to close and cleanup etc..
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
    if let Some(websocket) = dial_gateway(&mut agent.reginfo, &agent.pkt_pool, &agent.tcp_pool) {
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
    let cur_reginfo = REGINFO_CHANGED.load(Relaxed);
    if agent.reginfo_changed == cur_reginfo {
        return;
    }
    agent.reginfo_changed = cur_reginfo;
    unsafe { agent.reginfo = *REGINFO.take().unwrap() };
    agent.idp_onboarded = true;
    // Trigger resend of onboard info
    agent.gw_onboarded = false;
}

fn monitor_gw(agent: &mut AgentInfo, poll: &mut Poll) {
    // If we want the agent to be in all-direct mode, dont bother about gateway
    if DIRECT.load(Relaxed) == 1 {
        return;
    }

    // Will be readded later down below
    let gw_tun_info = agent.tuns.remove(&GWTUN_IDX);
    if let Some(mut gw_tun_tun) = gw_tun_info {
        let gw_tun = &mut gw_tun_tun.tun();
        if gw_tun.tun.is_closed(0) {
            STATS_GWUP.store(0, Relaxed);
            STATS_NUMFLAPS.fetch_add(1, Relaxed);
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
            STATS_GWUP.store(1, Relaxed);
            match gw_tun.flows {
                TunFlow::OneToMany(ref mut tun_flows) => {
                    tun_flows.shrink_to_fit();
                    STATS_GWFLOWS.store(tun_flows.len() as i32, Relaxed);
                }
                _ => {}
            }
            // Readded
            agent.tuns.insert(GWTUN_IDX, gw_tun_tun);
        }

        let now = Instant::now();
        if now > agent.last_flap {
            STATS_LASTFLAP.store((now - agent.last_flap).as_secs() as i32, Relaxed);
        }
    } else {
        STATS_LASTFLAP.store(0, Relaxed);
        new_gw(agent, poll);
    }
}

fn app_transport(
    fd: i32,
    platform: usize,
    mtu: usize,
    pkt_pool: &Arc<Pool<Vec<u8>>>,
) -> Box<dyn Transport> {
    let mut vpn_tun = Fd::new_client(fd, platform, mtu, pkt_pool.clone());
    match vpn_tun.dial() {
        Err(e) => {
            error!("app dial failed {}", e.detail);
        }
        _ => (),
    }
    Box::new(vpn_tun)
}

// Send one dummy handshake packet to trigger a new stream to the server,
// the server is not going to initiate anything to us. This will send the
// handshake in an async fashion till the data is fully sent. And till we
// initiate a stream (because of this handshake) to the server, the server
// is not gonna send us back anything
fn monitor_tcp_vpn(agent: &mut AgentInfo, poll: &mut Poll) {
    if agent.tcp_vpn == 0 || agent.tcp_vpn_handshake.is_none() {
        return;
    }

    match agent
        .vpn_tun
        .tun
        .write(0, agent.tcp_vpn_handshake.take().unwrap())
    {
        Err((d, e)) => match e.code {
            EWOULDBLOCK => {
                error!(
                    "Wrote handshake to tcp pkt server, error {}, {}",
                    e,
                    d.is_none()
                );
                agent.tcp_vpn_handshake = d;
                agent
                    .vpn_tun
                    .tun
                    .event_register(Token(VPNTUN_IDX), poll, RegType::Rereg)
                    .ok();
            }
            _ => panic!("Cannot handshake with  tcp vpn server"),
        },
        Ok(_) => error!("Wrote handshake to tcp vpn server succesfully"),
    }
}

fn monitor_fd_vpn(agent: &mut AgentInfo, poll: &mut Poll) {
    let fd = VPNFD.load(Relaxed);
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
        let vpn_tun = app_transport(fd, agent.platform, agent.mtu, &agent.pkt_pool);
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
                tun.tun.close(0).ok();
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
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    tcp_pool: &Arc<Pool<Vec<u8>>>,
    nameip: &mut NameIP,
    _perf: &mut AgentPerf,
) {
    let mut keys = Vec::new();
    for (k, _) in parse_pending.iter_mut() {
        if let Some(f) = flows.get_mut(k) {
            if Instant::now() > f.creation_time + Duration::from_millis(SERVICE_PARSE_TIMEOUT) {
                // We couldnt parse the service, just use dest ip as service
                if f.service == "" {
                    f.service = k.dip.clone();
                    set_dest_agent(
                        k,
                        f,
                        reginfo,
                        tuns,
                        next_tun_idx,
                        poll,
                        gw_onboarded,
                        pkt_pool,
                        tcp_pool,
                    );
                }
                if let Some(data) = f.parse_pending.take() {
                    // Send the data queued up for parsing immediately
                    let data = Some(NxtBufs {
                        hdr: None,
                        bufs: vec![data],
                        headroom: 0,
                    });
                    if let Some(tx_sock) = tuns.get_mut(&f.tx_socket) {
                        flow_data_to_external(
                            k,
                            f,
                            data,
                            &mut tx_sock.tun(),
                            reginfo,
                            poll,
                            pkt_pool,
                            nameip,
                            _perf,
                        );
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

// The goal of this api is to handle cases where say someone is using an app on
// their phone, that app has some tcp sessions open and is in the middle of some
// read / write, and in the middle of that the user switches that app to
// the background. And on devices like apple ios, there is no activity by a
// background app, its completely suspended (I guess androind is the same?). So
// then we will have a case where a ton of inactive flows are lying around
// potentially holding on to buffers which they were using before they went inactive.
// So we come here and close such flows IF they happened to be holding buffers
// when they were switched to background. We dont have any problem if a flow is
// idle and its not holding onto buffers - which is the most common case when an
// active app has tcp/udp sessions that are idle - they will continue to be open,
// but they are not taking up any buffer space.
fn monitor_buffers(
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    flows_active: &mut HashMap<FlowV4Key, ()>,
) {
    let mut keys = Vec::new();
    let now = Instant::now();
    for (k, _) in flows_active.iter() {
        if let Some(mut f) = flows.get_mut(k) {
            let mut b = 0;
            if !f.rx_socket.idle(false) {
                // It can actually be one or two buffers (rx/tx/both), we dont
                // have that granular output from the idle() API.
                b += 1;
            }
            b += f.pending_rx.len();
            if f.pending_tx.is_some() {
                b += 1;
            }
            if now >= f.last_rdwr + Duration::from_secs(FLOW_BUFFER_HOG) {
                if b != 0 {
                    error!(
                        "Buffer close flow {} / {}, idle {}, pending_rx {}, pending_tx {}",
                        k,
                        f.service,
                        f.rx_socket.idle(false),
                        f.pending_rx.len(),
                        f.parse_pending.is_some()
                    );
                    flow_dead(k, f);
                }
                keys.push(k.clone());
                f.active = false;
            }
        }
    }
    for k in keys {
        flows_active.remove(&k);
    }
    flows_active.shrink_to_fit();
}

// Just punch the flow liveliness timestamp.
// The internet RFCs stipulate 4 hours for TCP idle flow, 5 minutes for UDP idle flow -
// we have made it some more shorter here, that will pbbly have to be bumped up to match
// the RFC eventually. And for dns we are being super aggressive here, cleaning up in 30 seconds.
fn flow_alive(key: &FlowV4Key, flow: &mut FlowV4) {
    if flow.dead {
        return;
    }
    flow.last_rdwr = Instant::now();
    if key.proto == common::TCP {
        flow.cleanup_after = CLEANUP_TCP_IDLE;
    } else {
        if key.dport == 53 || key.dport == 853 {
            flow.cleanup_after = CLEANUP_UDP_DNS;
        } else {
            flow.cleanup_after = CLEANUP_UDP_IDLE;
        }
    }
}

fn flow_dead(_key: &FlowV4Key, flow: &mut FlowV4) {
    if flow.dead {
        return;
    }
    // Now let monitor_flows() clean up all other structures that has references/keys
    // to this flow and release the flow itself from flow table
    flow.dead = true;
    flow.cleanup_after = CLEANUP_NOW;
}

// Send notifications to all parties (local kernel sockets, remote cluster etc..) that
// this flow is closed. ie generate a FIN/RST to local and direct sockets if the flow is
// direct,and send a message/signal to cluster if the flow is via nextensio. And then
// cleanup EVERYTHING THAT CONSUMES MEMORY **RIGHT AWAY**. And we let the flow hang around
// for a few more seconds to be cleaned up by monitor_flows - because even after we close
// the flow, we might get a few packets and we dont want to try and create new flow for
// those old packets etc..
// NOTE: The tx_socket parameter HAS to be non-None if the flow is already associated with
// a tx socket. ONLY in cases where flow is closed before tx-socket is found can it be
// passed as None
fn flow_close(
    _key: &FlowV4Key,
    flow: &mut FlowV4,
    tx_socket: &mut Option<&mut TunInfo>,
    poll: &mut Poll,
) {
    // Tell all parties local and remote that the flow is closed
    if let Some(tx_socket) = tx_socket {
        let mut tx_socket = tx_socket.tun();
        // There maybe two streams - one going to external via tx socket and one coming
        // from external again via tx socket (forward and return). Close both
        tx_socket.tun.close(flow.tx_stream).ok();
        if let Some(rx_stream) = flow.rx_stream {
            tx_socket.tun.close(rx_stream).ok();
        }
        if flow.tx_socket != GWTUN_IDX {
            tx_socket
                .tun
                .event_register(Token(flow.tx_socket), poll, RegType::Dereg)
                .ok();
        }
        tx_socket.pending_rx -= flow.pending_rx.len();
    }
    flow.rx_socket.close(0).ok();
    // Unregister the poller so we dont keep polling till the flow is cleaned
    // up which can be many seconds away
    flow.rx_socket
        .event_register(Token(flow.rx_socket_idx), poll, RegType::Dereg)
        .ok();

    // Free all memory occupying stuff
    flow.rx_socket.idle(true);
    flow.pending_rx.clear();
    flow.pending_tx = None;
    flow.parse_pending = None;
    flow.pending_tx = None;
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
    let mut tx_sock;
    if tx_sock_in.is_some() {
        tx_sock = tx_sock_in;
    } else {
        tx_sock = tuns.get_mut(&f.tx_socket);
    }
    flow_close(k, f, &mut tx_sock, poll);

    if let Some(tx_socket) = tx_sock {
        let tx_socket = tx_socket.tun();
        match tx_socket.flows {
            TunFlow::OneToMany(ref mut sock_flows) => {
                sock_flows.remove(&f.tx_stream);
                if let Some(rx_stream) = f.rx_stream {
                    sock_flows.remove(&rx_stream);
                }
            }
            _ => {}
        }
        if f.tx_socket != GWTUN_IDX {
            // Gateway socket is monitored seperately, if the flow is dead, just
            // deregister the tx socket if its a 1:1 (direct flow case) socket
            tuns.remove(&f.tx_socket);
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
    pkt_pool: &Arc<Pool<Vec<u8>>>,
    tcp_pool: &Arc<Pool<Vec<u8>>>,
    nameip: &NameIP,
) {
    STATS_NUMFLOWS.store(flows.len() as i32, Relaxed);

    let mut udp = 0;
    let mut dns = 0;
    let mut tcp = 0;
    let mut pending_rx = 0;
    let mut pending_tx = 0;
    let mut idle = 0;

    let mut keys = Vec::new();
    for (k, f) in flows.iter_mut() {
        let rdwr = f.last_rdwr + Duration::from_secs(f.cleanup_after as u64);
        let now = Instant::now();
        if now > rdwr {
            flow_terminate(k, f, parse_pending, None, tuns, flows_active, poll);
            keys.push(k.clone());
        }
        if k.proto == common::TCP {
            tcp += 1;
        } else {
            if k.dport == 53 || k.dport == 853 {
                dns += 1;
            }
            udp += 1;
        }
        if !f.rx_socket.idle(false) {
            // It can actually be one or two buffers (rx/tx/both), we dont
            // have that granular output from the idle() API.
            idle += 1;
        }
        if !f.pending_rx.is_empty() {
            pending_rx += f.pending_rx.len();
        }
        if f.pending_tx.is_some() {
            pending_tx += 1;
        }
    }
    for k in keys {
        flows.remove(&k);
    }
    flows.shrink_to_fit();

    let mut gw_pending = 0;
    if let Some(tun) = tuns.get_mut(&GWTUN_IDX) {
        gw_pending = tun.tun().pending_rx;
    }
    error!(
        "tcp {}, udp {}, dns {}, pkt bufs {}, tcp bufs {}, pending rx {} / tx {}, idle {}, gw pending {}, dns {}, rdns{}",
        tcp,
        udp,
        dns,
        pkt_pool.len(),
        tcp_pool.len(),
        pending_rx,
        pending_tx,
        idle,
        gw_pending,
        nameip.dns.len(), nameip.rdns.len()
    );
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
                EWOULDBLOCK => {
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
        tun: Box::new(WebProxy::new_client(
            NXT_AGENT_PROXY,
            agent.pkt_pool.clone(),
        )),
        pending_tx: VecDeque::with_capacity(0),
        tx_ready: true,
        flows: TunFlow::NoFlow,
        proxy_client: false,
        pending_rx: 0,
    };
    let mut success = false;
    match agent.proxy_tun.tun.listen() {
        Ok(_) => success = true,
        Err(e) => match e.code {
            EWOULDBLOCK => success = true,
            _ => {
                error!("Cannot bind {}", e);
            }
        },
    }
    if success {
        agent
            .proxy_tun
            .tun
            .event_register(WEBPROXY_POLL, poll, RegType::Reg)
            .ok();
    } else {
        error!("Cannot listen to port {}", NXT_AGENT_PROXY);
    }
}

fn agent_init_pools(agent: &mut AgentInfo, mtu: u32, highmem: u32) {
    // The mtu of the interface is set to the same as the buffer size, so we can READ packets as
    // large as the buffer size. But some platforms (like android) seems to perform poor when we
    // try to send packets closer to the interface mtu (mostly when mtu is large like 64K) and
    // hence we want to keep the mtu  size different from the mtu. We control the size of the
    // tcp packets we receive to be mtu by doing mss-adjust when the tcp session is created
    agent.mtu = mtu as usize;

    // This will change over time - there can really be no "common max payload/buffer", the buffer
    // sizes will depend on each driver/transport. For now its a "common" parameter
    common::set_maxbuf(MAXPAYLOAD);

    // The 2*mtu is used to make sure smoltcp can fit in a full mtu sized udp packet into this
    // buffer. See README.md in l3proxy/ in common repo
    let pktbuf_len = std::cmp::min(MINPKTBUF, (2 * mtu as usize).next_power_of_two());
    // We want the parse buffer to fit in just one packet to keep it simple
    assert!(PARSE_MAX <= pktbuf_len);

    // Theres not a lot of fancy math here as of today. The 'highmem: 1' platforms are usually
    // laptops and highmem: 0 is a mobile device. So we just use half the memory on a mobile device
    // compared to a laptop thats about it. Note that we might be able to bring these numbers down
    // even lesser, will bring it down after this software gets more runtime on various devices.
    // Note that the npkts usually has to be at least the MAXPAYLOAD/mtu (ie the number of pkts
    // to send one full size tcp payload) for better performance
    agent.npkts = 64 * (highmem as usize + 1);
    agent.ntcp = 22 * (highmem as usize + 1);
    agent.pkt_pool = Arc::new(Pool::new(agent.npkts, || Vec::with_capacity(pktbuf_len)));
    agent.tcp_pool = Arc::new(Pool::new(agent.ntcp, || Vec::with_capacity(MAXPAYLOAD)));
}

// Instead of getting vpn packets from an OS file descriptor interface,
// we are being given packets over a TCP socket
fn tcp_vpn_init(agent: &mut AgentInfo, poll: &mut Poll) {
    let headers = HashMap::new();
    let mut vpn_tun = WebSession::new_client(
        vec![],
        "127.0.0.1",
        agent.tcp_vpn as usize,
        headers,
        agent.pkt_pool.clone(),
        agent.tcp_pool.clone(),
        0,
    );
    loop {
        match vpn_tun.dial() {
            Err(e) => match e.code {
                EWOULDBLOCK => {
                    error!("Dialled tcp vpn server, ewouldblock");
                    break;
                }
                _ => error!("Dial tcp vpn server  failed: {}", e.detail),
            },
            Ok(_) => {
                error!("Dialled tcp vpn server, Ok");
                break;
            }
        }
    }

    let vpn_tun = Box::new(vpn_tun);
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
            tun.tun.close(0).ok();
            panic!("TCP App transport register failed {}", format!("{}", e));
        }
        _ => {
            agent.vpn_tun = tun;
            error!("TCP App Transport Registered");
            ()
        }
    }

    let mut hdr = NxtHdr::default();
    let f = NxtFlow::default();
    hdr.hdr = Some(Hdr::Flow(f));
    // We better get at least one packet here, we havent used any yet!
    let mut pkt = pool_get(agent.pkt_pool.clone()).unwrap();
    pkt.clear();
    pkt.extend_from_slice(br"Hello World");
    agent.tcp_vpn_handshake = Some(NxtBufs {
        bufs: vec![pkt],
        headroom: 0,
        hdr: Some(hdr),
    });
}

fn agent_main_thread(platform: u32, direct: u32, mtu: u32, highmem: u32, tcp_vpn: u32) {
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

    #[cfg(target_os = "windows")]
    log::set_boxed_logger(Box::new(winlog::WinLogger::new("Nextensio")))
        .map(|()| log::set_max_level(LevelFilter::Error))
        .ok();

    error!(
        "Agent init called, platform {}, direct {},mtu {}, highmem {}",
        platform, direct, mtu, highmem
    );

    let mut poll = match Poll::new() {
        Err(e) => panic!("Cannot create a poller {:?}", e),
        Ok(p) => p,
    };

    let mut events = Events::with_capacity(2048);

    let mut agent = AgentInfo::default();
    if direct == 1 {
        DIRECT.store(1, Relaxed);
    }
    agent.platform = platform as usize;
    agent_init_pools(&mut agent, mtu, highmem);
    agent.next_tun_idx = TUN_START;
    agent.tcp_vpn = tcp_vpn;

    if agent.tcp_vpn != 0 {
        tcp_vpn_init(&mut agent, &mut poll);
    }

    let ratio = MAXPAYLOAD / mtu as usize;

    proxy_init(&mut agent, &mut poll);

    let mut flow_ager = Instant::now();
    let mut service_parse_ager = Instant::now();
    let mut monitor_ager = Instant::now();
    let mut buffer_monitor = Instant::now();
    let mut last_onboard = Instant::now();
    let mut dns_monitor = Instant::now();

    loop {
        let hundred_ms = Duration::from_millis(SERVICE_PARSE_TIMEOUT);
        let now = Instant::now();
        match poll.poll(&mut events, Some(hundred_ms)) {
            Err(e) => error!("Error polling {:?}, retrying", e),
            Ok(_) => {}
        }

        for event in events.iter() {
            match event.token() {
                VPNTUN_POLL => {
                    if event.is_readable() {
                        vpntun_rx(
                            ratio,
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
                            agent.mtu,
                            &mut agent.flows_active,
                            &mut agent.check_tuns,
                            &agent.pkt_pool,
                            &agent.tcp_pool,
                            &mut agent.nameip,
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
                                    &mut agent.check_tuns,
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
                                    &mut agent.check_tuns,
                                    &agent.pkt_pool,
                                    &agent.tcp_pool,
                                    &mut agent.nameip,
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
                                    &mut tun_info.tun(),
                                    idx,
                                    &mut agent.flows,
                                    &mut agent.vpn_rx,
                                    &mut agent.vpn_tx,
                                    &mut poll,
                                    &mut agent.check_tuns,
                                    &mut agent.flows_active,
                                    &mut agent.gw_onboarded,
                                );
                            }
                            if event.is_writable() {
                                external_sock_tx(
                                    &mut tun_info.tun(),
                                    &mut agent.flows,
                                    &agent.reginfo,
                                    &mut poll,
                                    &mut agent.perf,
                                    &mut agent.vpn_rx,
                                    &mut agent.vpn_tx,
                                    &agent.pkt_pool,
                                    &mut agent.nameip,
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
                vpntun_tx(&mut agent.vpn_tun, &mut agent.vpn_tx, &mut poll);
            }
        }

        // We stopped reading some tunnels because they were downloading data
        // faster than the app can handle. So when the app has drained the data,
        // we start reading from those tunnels again.
        if !agent.check_tuns.is_empty() {
            let mut check_tuns = HashMap::new();
            for (idx, _) in agent.check_tuns {
                if let Some(mut tun_info) = agent.tuns.remove(&idx) {
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
                        let rereg = proxyclient_rx(
                            tun_info,
                            &mut agent.flows,
                            &mut agent.parse_pending,
                            &mut agent.tuns,
                            Token(idx),
                            &mut agent.next_tun_idx,
                            &mut poll,
                            agent.gw_onboarded,
                            &agent.reginfo,
                            &mut check_tuns,
                            &agent.pkt_pool,
                            &agent.tcp_pool,
                            &mut agent.nameip,
                            &mut agent.perf,
                        );
                        if rereg.is_some() {
                            agent.tuns.insert(idx, rereg.unwrap());
                        }
                    } else {
                        external_sock_rx(
                            &mut tun_info.tun(),
                            Token(idx),
                            &mut agent.flows,
                            &mut agent.vpn_rx,
                            &mut agent.vpn_tx,
                            &mut poll,
                            &mut check_tuns,
                            &mut agent.flows_active,
                            &mut agent.gw_onboarded,
                        );
                        agent.tuns.insert(idx, tun_info);
                    }
                }
            }
            agent.check_tuns = check_tuns;
        }

        if !agent.gw_onboarded && agent.idp_onboarded {
            if now > last_onboard + Duration::from_millis(ONBOARD_RETRY) {
                if let Some(gw_tun) = agent.tuns.get_mut(&GWTUN_IDX) {
                    send_onboard_info(&mut agent.reginfo, &mut gw_tun.tun());
                    last_onboard = now;
                }
            }
        }

        // Note that we have a poll timeout of two seconds, but packets can keep the loop busy
        // so make sure we monitor only every two secs
        if now > monitor_ager + Duration::from_secs(MONITOR_CONNECTIONS) {
            monitor_onboard(&mut agent);
            monitor_gw(&mut agent, &mut poll);
            monitor_fd_vpn(&mut agent, &mut poll);
            monitor_tcp_vpn(&mut agent, &mut poll);
            monitor_ager = now;
        }
        if now > service_parse_ager + Duration::from_millis(SERVICE_PARSE_TIMEOUT) {
            monitor_parse_pending(
                &mut agent.flows,
                &mut agent.parse_pending,
                &mut agent.tuns,
                &mut agent.reginfo,
                &mut poll,
                &mut agent.next_tun_idx,
                agent.gw_onboarded,
                &agent.pkt_pool,
                &agent.tcp_pool,
                &mut agent.nameip,
                &mut agent.perf,
            );
            service_parse_ager = now;
        }
        if now > flow_ager + Duration::from_secs(MONITOR_FLOW_AGE) {
            // Check the flow aging only once every 30 seconds
            monitor_flows(
                &mut poll,
                &mut agent.flows,
                &mut agent.parse_pending,
                &mut agent.tuns,
                &mut agent.flows_active,
                &agent.pkt_pool,
                &agent.tcp_pool,
                &agent.nameip,
            );
            flow_ager = now;
        }
        if now > buffer_monitor + Duration::from_secs(MONITOR_IDLE_BUFS) {
            monitor_buffers(&mut agent.flows, &mut agent.flows_active);
            buffer_monitor = now;
        }
        if now > dns_monitor + Duration::from_secs(MONITOR_DNS) {
            dns::monitor_dns(&mut agent.nameip);
            dns_monitor = now;
        }
    }
}

// NOTE1: PLEASE ENSURE THAT THIS API IS CALLED ONLY ONCE BY THE PLATFORM
//
// NOTE2: This is a for-ever loop inside, so call this from a seperate thread in
// the platform (android/ios/linux). We can launch a thread right in here
// and that works, but at least on android there is this problem of that thread
// mysteriously vanishing after a few hours, maybe its becuase the thread created
// here might not be the right priority etc.. ? The thread created from android
// itself seems to work fine and hence we are leaving the thread creation to the
// platform so it can choose the right priority etc..
//
// NOTE3: windows as of today calls rust from golang - I am not sure if a goroutine
// plays well if we block it from rust (agent_main_thread blocks for ever).
// Creating a new thread just for that reason. And golang doesnt have any way of
// spawning an OS thread, hence doing it here
#[no_mangle]
pub unsafe extern "C" fn agent_init(
    platform: u32,
    direct: u32,
    mtu: u32,
    highmem: u32,
    tcp_vpn: u32,
) {
    AGENT_STARTED.store(1, Relaxed);
    if platform == 2 {
        thread::spawn(move || agent_main_thread(platform, direct, mtu, highmem, tcp_vpn));
    } else {
        agent_main_thread(platform, direct, mtu, highmem, tcp_vpn);
    }
}

#[no_mangle]
pub unsafe extern "C" fn agent_started() -> usize {
    AGENT_STARTED.load(Relaxed)
}

// We EXPECT the fd provied to us to be already non blocking
#[no_mangle]
pub unsafe extern "C" fn agent_on(fd: i32) {
    let old_fd = VPNFD.load(Relaxed);
    error!("Agent on, old {}, new {}", old_fd, fd);
    VPNFD.store(fd, Relaxed);
}

#[no_mangle]
pub unsafe extern "C" fn agent_default_route(bindip: u32) {
    BINDIP.store(bindip, Relaxed);
}

#[no_mangle]
pub unsafe extern "C" fn agent_off() {
    let fd = VPNFD.load(Relaxed);
    error!("Agent off {}", fd);
    VPNFD.store(0, Relaxed);
}

#[no_mangle]
pub unsafe extern "C" fn onboard(info: CRegistrationInfo) {
    REGINFO = Some(Box::new(creginfo_translate(info)));
    REGINFO_CHANGED.fetch_add(1, Relaxed);
}

#[no_mangle]
pub unsafe extern "C" fn agent_stats(stats: *mut AgentStats) {
    (*stats).gateway_up = STATS_GWUP.load(Relaxed);
    (*stats).gateway_flaps = STATS_NUMFLAPS.load(Relaxed);
    (*stats).last_gateway_flap = STATS_LASTFLAP.load(Relaxed);
    (*stats).gateway_flows = STATS_GWFLOWS.load(Relaxed);
    (*stats).total_flows = STATS_NUMFLOWS.load(Relaxed);
}
