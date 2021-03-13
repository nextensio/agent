#[cfg(target_os = "android")]
use android_logger::Config;
use common::as_u32_be;
use common::{
    decode_ipv4,
    nxthdr::{nxt_hdr::Hdr, nxt_hdr::StreamOp, NxtHdr, NxtOnboard},
    FlowV4Key, NxtBufs, NxtErr, RegType, Transport,
};
use dummy::Dummy;
use fd::Fd;
use l3proxy::Socket;
use log::{error, Level};
use mio::{Events, Poll, Token};
use netconn::NetConn;
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::SystemTime;
use std::{collections::HashMap, time::Duration, time::Instant};
use std::{sync::atomic::AtomicI32, thread};
use websock::WebSession;

// These are atomic because rust will complain loudly about mutable global variables
static APPFD: AtomicI32 = AtomicI32::new(0);
static INITED: AtomicI32 = AtomicI32::new(0);
static DIRECT: AtomicI32 = AtomicI32::new(0);

const _UNUSED_IDX: usize = 0;
const APPTUN_IDX: usize = 1;
const GWTUN_IDX: usize = 2;
const TUN_START: usize = 3;
const GWTUN: Token = Token(GWTUN_IDX);
const APPTUN: Token = Token(APPTUN_IDX);

const CLEANUP_NOW: usize = 5; // 5 seconds
const CLEANUP_TCP_HALFOPEN: usize = 30; // 30 seconds
const CLEANUP_TCP_IDLE: usize = 60 * 60; // one hour
const CLEANUP_UDP_IDLE: usize = 4 * 60; // 4 minutes
const CLEANUP_UDP_DNS: usize = 30; // 30 seconds

#[derive(Default)]
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

struct FlowV4 {
    rx_socket: Box<dyn Transport>,
    rx_stream: Option<u64>,
    tx_stream: u64,
    tx_socket: usize,
    pending_tx: Option<NxtBufs>,
    pending_rx: VecDeque<NxtBufs>,
    dead_time: Instant,
    cleanup_after: usize,
    dead: bool,
    pending_tx_qed: bool,
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
}

impl Default for Tun {
    fn default() -> Self {
        Tun {
            tun: Box::new(Dummy::default()),
            pending_tx: VecDeque::with_capacity(0),
            tx_ready: true,
            flows: TunFlow::NoFlow,
        }
    }
}

#[derive(Default)]
struct AgentInfo {
    idp_onboarded: bool,
    gw_onboarded: bool,
    platform: usize,
    reginfo: RegistrationInfo,
    app_fd: i32,
    app_tx: VecDeque<(usize, Vec<u8>)>,
    app_rx: VecDeque<(usize, Vec<u8>)>,
    flows: HashMap<FlowV4Key, FlowV4>,
    tuns: HashMap<usize, Tun>,
    next_tun_idx: usize,
    gw_tun: Tun,
    app_tun: Tun,
}

fn dummy_onboard(agent: &mut AgentInfo) {
    // TODO: do proper okta onboarding
    agent.idp_onboarded = false;
    agent.reginfo = RegistrationInfo {
        host: "gatewaytesta.nextensio.net".to_string(),
        access_token: "foobar".to_string(),
        connect_id: "test1-nextensio-net".to_string(),
        domains: Vec::new(),
        ca_cert: vec![1, 2, 3, 4],
        userid: "test1@nextensio.net".to_string(),
        uuid: "123e4567-e89b-12d3-a456-426655440000".to_string(),
        services: vec!["test1-nextensio-net".to_string()],
    };
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
    flow.dead_time = Instant::now();
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
        drop(flow.pending_rx.clear());
        flow.pending_tx = None;
    }
}

fn flow_close(key: &FlowV4Key, flow: &mut FlowV4, tx_socket: &mut Box<dyn Transport>) {
    flow.rx_socket.close(0).ok();
    flow_alive(key, flow, false);
    tx_socket.close(flow.tx_stream).ok();
    if let Some(rx_stream) = flow.rx_stream {
        tx_socket.close(rx_stream).ok();
    }
}

fn flow_new(
    key: FlowV4Key,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    tuns: &mut HashMap<usize, Tun>,
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
        let dest = Ipv4Addr::new(
            ((key.dip >> 24) & 0xFF) as u8,
            ((key.dip >> 16) & 0xFF) as u8,
            ((key.dip >> 8) & 0xFF) as u8,
            (key.dip & 0xFF) as u8,
        );
        let mut tun = NetConn::new_client(dest, key.dport as usize, key.proto, true);
        // TODO: The 200ms is a random timeout. We are not really expected to send anything
        // out via direct, this agent is for via-nextensio apps. So this shouldnt matter for
        // the time being
        match tun.dial(Some(Duration::from_millis(200))) {
            Err(_) => {
                return;
            }
            Ok(()) => {}
        }
        tx_stream = tun.new_stream();
        *next_tun_idx = tx_socket + 1;
        let mut tun = Tun {
            tun: Box::new(tun),
            pending_tx: VecDeque::with_capacity(1),
            tx_ready: true,
            flows: TunFlow::OneToOne(key),
        };
        match tun.tun.event_register(Token(tx_socket), poll, RegType::Reg) {
            Err(e) => {
                error!("Direct transport register failed {}", format!("{}", e));
                tun.tun.close(0).ok();
                return;
            }
            Ok(_) => {}
        }
        tuns.insert(tx_socket, tun);
    } else if gw_onboarded {
        tx_socket = GWTUN_IDX;
        if let Some(gw_tun) = tuns.get_mut(&GWTUN_IDX) {
            tx_stream = gw_tun.tun.new_stream();
            match gw_tun.flows {
                TunFlow::OneToMany(ref mut tun_flows) => {
                    tun_flows.insert(tx_stream, key);
                }
                _ => panic!("We expect a hashmap for gateway flows"),
            }
        } else {
            return;
        }
    } else {
        return;
    }

    let cleanup_after;
    if key.proto == common::TCP {
        cleanup_after = CLEANUP_TCP_HALFOPEN;
    } else {
        cleanup_after = CLEANUP_UDP_IDLE;
    }

    let f = FlowV4 {
        rx_socket: Box::new(Socket::new_client(key, 1500)),
        rx_stream: None,
        tx_stream,
        tx_socket,
        pending_tx: None,
        pending_rx: VecDeque::with_capacity(1),
        dead_time: Instant::now(),
        cleanup_after,
        dead: false,
        pending_tx_qed: false,
    };
    flows.insert(key, f);
}

// Today this dials websocket, in future with different possible transports,
// this can dial some other protocol, but eventually it returns a Transport trait
fn dial_gateway(reginfo: &RegistrationInfo) -> WebSession {
    let mut headers = HashMap::new();
    headers.insert(
        "x-nextensio-connect".to_string(),
        reginfo.connect_id.clone(),
    );
    let mut websocket = WebSession::new_client(vec![0], &reginfo.host, 443, headers, true);
    loop {
        match websocket.dial(None) {
            Err(e) => {
                error!(
                    "Dial gateway {} failed: {}, sleeping 2 seconds",
                    &reginfo.host, e.detail
                );
                thread::sleep(Duration::new(2, 0));
            }
            Ok(_) => break,
        }
    }
    websocket
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
    data: NxtBufs,
    app_rx: &mut VecDeque<(usize, Vec<u8>)>,
    app_tx: &mut VecDeque<(usize, Vec<u8>)>,
    poll: &mut Poll,
) {
    if let Some(flow) = flows.get_mut(key) {
        if !flow.dead {
            if flow.rx_stream.is_none() && stream != flow.tx_stream {
                flow.rx_stream = Some(stream);
                match tun.flows {
                    TunFlow::OneToMany(ref mut tun_flows) => {
                        tun_flows.insert(stream, *key);
                    }
                    _ => {}
                }
            }
            flow.pending_rx.push_back(data);
            flow_alive(&key, flow, true);
            flow_data_from_gateway(&key, flow, &mut tun.tun, app_rx, poll);
            // this call will generate packets to be sent out back to the kernel
            // into the app_tx queue which will be processed in apptun_tx
            flow.rx_socket.poll(app_rx, app_tx);
            assert!(app_rx.len() == 0);
        }
    }
}

// Read in data coming in from gateway (or direct), find the corresponding flow
// and send the data to the flow. For data coming from the gateway, it comes with some
// inbuilt flow control mechanisms - we advertise how much data we can receive per flow
// to the gateway, so we wont have a situation of a flow having too much stuff backed up.
// But for direct flows if we find that our flow is getting backed up, we just stop reading
// from the direct socket anymore till the flow queue gets drained
fn gwtun_rx(
    tun: &mut Tun,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    app_rx: &mut VecDeque<(usize, Vec<u8>)>,
    app_tx: &mut VecDeque<(usize, Vec<u8>)>,
    poll: &mut Poll,
) {
    match tun.flows {
        TunFlow::OneToOne(ref k) => {
            // If its a 1:1 tunnel, and if we already have a backlog of data, then dont pull in more
            // If its a 1:many tunnel, we will send a flow control message back to the sender indicating
            // receive readiness, see api flow_rx_data()
            if let Some(flow) = flows.get_mut(k) {
                if flow.pending_rx.len() > 1 {
                    return;
                }
            }
        }
        _ => {}
    }
    loop {
        let ret = tun.tun.read();
        match ret {
            Err(x) => match x.code {
                NxtErr::EWOULDBLOCK => {
                    return;
                }
                _ => {
                    // This will trigger monitor_gw() to cleanup flows etc.
                    tun.tun.close(0).ok();
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
                                        flow_close(k, f, &mut tun.tun);
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
                            Hdr::Flow(flow) => {
                                let sipb: Result<Ipv4Addr, _> = flow.source.parse();
                                let dipb: Result<Ipv4Addr, _> = flow.dest.parse();
                                // This has to be a corrupt packet, otherwise we can have a
                                // garbage ip address come in. We cant keep the session/tun open
                                // with even one garbage packet coming in on it
                                if sipb.is_err() || dipb.is_err() {
                                    tun.tun.close(0).ok();
                                    return;
                                }
                                let sip = as_u32_be(&sipb.unwrap().octets());
                                let dip = as_u32_be(&dipb.unwrap().octets());
                                let key = FlowV4Key {
                                    sip,
                                    dip,
                                    sport: flow.sport as u16,
                                    dport: flow.dport as u16,
                                    proto: flow.proto as usize,
                                };
                                flow_rx_data(stream, tun, &key, flows, data, app_rx, app_tx, poll);
                            }
                        }
                    }
                } else {
                    let key;
                    match tun.flows {
                        TunFlow::OneToOne(ref k) => {
                            key = *k;
                        }
                        _=> panic!("We either need an nxthdr to identify the flow or we need the tun to map 1:1 to the flow"),
                    }
                    flow_rx_data(stream, tun, &key, flows, data, app_rx, app_tx, poll);
                    // If its a 1:1 tunnel, and if we already have a backlog of data, then dont pull in more
                    // If its a 1:many tunnel, we will send a flow control message back to the sender indicating
                    // receive readiness, see api flow_rx_data()
                    if let Some(flow) = flows.get_mut(&key) {
                        if flow.pending_rx.len() > 1 {
                            return;
                        }
                    }
                }
            }
        }
    }
}

fn gwtun_tx(tun: &mut Tun, flows: &mut HashMap<FlowV4Key, FlowV4>) {
    while let Some(key) = tun.pending_tx.pop_front() {
        if let Some(flow) = flows.get_mut(&key) {
            if !flow.dead {
                flow.pending_tx_qed = false;
                flow_data_to_gateway(&key, flow, tun);
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

// Now lets see if the smoltcp FSM deems that we have a payload to
// be read. Before that see if we had any payload pending to be processed
// and if so process it. The payload might be sent to the gateway or direct.
fn flow_data_to_gateway(key: &FlowV4Key, flow: &mut FlowV4, tx_socket: &mut Tun) {
    while tx_socket.tx_ready {
        let tx;
        if flow.pending_tx.is_some() {
            tx = flow.pending_tx.take().unwrap();
        } else {
            tx = match flow.rx_socket.read() {
                Ok((_, t)) => t,
                Err(e) => match e.code {
                    NxtErr::EWOULDBLOCK => return,
                    _ => {
                        flow_close(key, flow, &mut tx_socket.tun);
                        return;
                    }
                },
            }
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
                        tx_socket.pending_tx.push_back(*key);
                        flow.pending_tx_qed = true;
                    }
                    return;
                }
                _ => {
                    flow_close(key, flow, &mut tx_socket.tun);
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
fn flow_data_from_gateway(
    key: &FlowV4Key,
    flow: &mut FlowV4,
    gateway_sock: &mut Box<dyn Transport>,
    app_rx: &mut VecDeque<(usize, Vec<u8>)>,
    poll: &mut Poll,
) {
    if flow.dead {
        return;
    }
    while let Some(rx) = flow.pending_rx.pop_front() {
        match flow.rx_socket.write(0, rx) {
            Err((data, e)) => match e.code {
                NxtErr::EWOULDBLOCK => {
                    // The stack cant accept these pkts now, return the data to the head again
                    flow.pending_rx.push_front(data.unwrap());
                    assert!(app_rx.len() == 0);
                    return;
                }
                _ => {
                    flow_close(key, flow, gateway_sock);
                    return;
                }
            },
            Ok(_) => {
                // See if the data we just gave the tcp/udp stack will be spit out
                // by the stack as packets to be sent in the app_tx queue
                assert!(app_rx.len() == 0);
            }
        }
    }
    flow.pending_rx.shrink_to_fit();
    if flow.pending_rx.len() <= 1 {
        if flow.tx_socket == GWTUN_IDX {
            // TODO: Send a flow control message to flow.rx_stream signalling
            // the other end to send more data
        } else {
            gateway_sock
                .event_register(Token(flow.tx_socket), poll, RegType::Rereg)
                .ok();
        }
    }
}

// let the smoltcp/l3proxy stack process a packet from the kernel stack by running its FSM. The rx_socket.poll
// will read from the app_rx queue and potentially write data back to app_tx queue. app_rx and app_tx are just
// a set of global queues shared by all flows. Its easy to understand why app_tx is global since Tx from all
// flows have to go out of the same tun back to the kernel anyways. The reason app_rx is also global is because
// really nothing remains 'pending' in the app_rx queue after the poll below is called, the smoltcp stack will
// consume the pkt regardless of whether it could process it or not. So after the poll, the app_rx queue goes
// empty, so why have one queue per flow !
// NOTE1: At a later point if we have some other tcp/udp stack that does things differently, we can always have
// one rx queue per flow, its just saving some memory by having a global queue, thats about it
// NOTE2: Just read one packet, and process it and then send out a response if any triggered by that packet
// and then re-register for the next packet. This seems provide a more "cripsy" response to webpage
// loads than processing a bunch of rx packets together. That might also be because the smoltcp stack
// will just drop rx packets if they exceed the smoltcp rx buffer size, so if we try to do a bunch of
// rx packets, maybe that just translates into lost packets
fn apptun_rx(
    tun: &mut Tun,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    app_rx: &mut VecDeque<(usize, Vec<u8>)>,
    app_tx: &mut VecDeque<(usize, Vec<u8>)>,
    tuns: &mut HashMap<usize, Tun>,
    next_tun_idx: &mut usize,
    poll: &mut Poll,
    gw_onboarded: bool,
) {
    let ret = tun.tun.read();
    match ret {
        Err(x) => match x.code {
            NxtErr::EWOULDBLOCK => {
                return;
            }
            _ => {
                // This will trigger monitor_appfd() to close and cleanup etc..
                tun.tun.close(0).ok();
                return;
            }
        },
        Ok((_, mut data)) => {
            for b in data.bufs {
                if let Some(key) = decode_ipv4(&b[data.headroom..]) {
                    let mut f = flows.get_mut(&key);
                    if f.is_none() {
                        flow_new(key, flows, tuns, next_tun_idx, poll, gw_onboarded);
                        f = flows.get_mut(&key);
                    }
                    if let Some(flow) = f {
                        if !flow.dead {
                            flow_alive(&key, flow, true);
                            app_rx.push_back((data.headroom, b));
                            // polling to see if the rx data will be available to be sent to the gateway below.
                            // The poll() call will also generate packets to be sent out back to the kernel
                            // into the app_tx queue which will be processed in apptun_tx
                            flow.rx_socket.poll(app_rx, app_tx);
                            assert!(app_rx.len() == 0);
                            if let Some(tx_sock) = tuns.get_mut(&flow.tx_socket) {
                                flow_data_to_gateway(&key, flow, tx_sock);
                                flow_data_from_gateway(&key, flow, &mut tx_sock.tun, app_rx, poll);
                            }
                            // poll again to see if packets from gateway can be sent back to the flow/app via agent_tx
                            flow.rx_socket.poll(app_rx, app_tx);
                            assert!(app_rx.len() == 0);
                        }
                    }
                }
                data.headroom = 0;
            }
        }
    }
}

fn apptun_tx(tun: &mut Tun, app_tx: &mut VecDeque<(usize, Vec<u8>)>) {
    while let Some((headroom, tx)) = app_tx.pop_front() {
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
                    app_tx.push_front((data.headroom, data.bufs.pop().unwrap()));
                    return;
                }
                _ => {
                    // This will trigger monitor_appfd() to close and cleanup etc..
                    tun.tun.close(0).ok();
                    return;
                }
            },
            Ok(_) => {}
        }
    }
    app_tx.shrink_to_fit();
}

fn new_gw(agent: &mut AgentInfo, poll: &mut Poll) {
    if !agent.idp_onboarded {
        return;
    }
    let websocket = dial_gateway(&mut agent.reginfo);
    let mut tun = Tun {
        tun: Box::new(websocket),
        pending_tx: VecDeque::with_capacity(1),
        tx_ready: true,
        flows: TunFlow::OneToMany(HashMap::new()),
    };

    match tun.tun.event_register(GWTUN, poll, RegType::Reg) {
        Err(e) => {
            error!("Gateway transport register failed {}", format!("{}", e));
            tun.tun.close(0).ok();
            return;
        }
        Ok(_) => {
            error!("Gateway Transport Registered");
            agent.tuns.insert(GWTUN_IDX, tun);
        }
    }
}

fn monitor_gw(agent: &mut AgentInfo, poll: &mut Poll) {
    if let Some(gw_tun) = agent.tuns.get_mut(&GWTUN_IDX) {
        if gw_tun.tun.is_closed(0) {
            error!("Gateway transport closed, try opening again");
            agent.gw_onboarded = false;
            gw_tun.tun.event_register(GWTUN, poll, RegType::Dereg).ok();
            close_gateway_flows(&mut agent.flows, gw_tun);
            agent.tuns.remove(&GWTUN_IDX);
            new_gw(agent, poll);
        } else {
            match gw_tun.flows {
                TunFlow::OneToMany(ref mut tun_flows) => tun_flows.shrink_to_fit(),
                _ => {}
            }
            return;
        }
    }
    new_gw(agent, poll);
}

fn app_transport(fd: i32, platform: usize) -> Box<dyn Transport> {
    let mut app_tun = Fd::new_client(fd, platform);
    match app_tun.dial(None) {
        Err(e) => {
            error!("app dial failed {}", e.detail);
        }
        _ => (),
    }
    Box::new(app_tun)
}

fn monitor_appfd(agent: &mut AgentInfo, poll: &mut Poll) {
    let fd = APPFD.load(std::sync::atomic::Ordering::Relaxed);
    if agent.app_fd != 0 && (agent.app_fd != fd || agent.app_tun.tun.is_closed(0)) {
        error!(
            "App transport closed, try opening again {}/{}/{}",
            agent.app_fd,
            fd,
            agent.app_tun.tun.is_closed(0)
        );
        agent.app_tun.tun.close(0).ok();
        agent
            .app_tun
            .tun
            .event_register(APPTUN, poll, RegType::Dereg)
            .ok();
        agent.app_fd = 0;
        if let Some(gw_tun) = agent.tuns.get_mut(&GWTUN_IDX) {
            close_gateway_flows(&mut agent.flows, gw_tun);
        }
        // After closing gateway flows, what is left is direct flows
        close_direct_flows(&mut agent.flows, &mut agent.tuns);
    }
    if agent.app_fd != fd {
        let app_tun = app_transport(fd, agent.platform);
        let mut tun = Tun {
            tun: app_tun,
            pending_tx: VecDeque::with_capacity(1),
            tx_ready: true,
            flows: TunFlow::NoFlow,
        };
        match tun.tun.event_register(APPTUN, poll, RegType::Reg) {
            Err(e) => {
                error!("App transport register failed {}", format!("{}", e));
                agent.app_tun.tun.close(0).ok();
                agent.app_fd = 0;
                return;
            }
            _ => {
                error!("App Transport Registered {}/{}", agent.app_fd, fd);
                agent.app_tun = tun;
                agent.app_fd = fd;
                ()
            }
        }
    }
}

// TODO: This can be made more effective by using some kind of timer wheel
// to sort the flows in the order of their expiry rather than having to walk
// through them all. Right now the use case is for a couple of hundred flows
// at most, so this might be just ok, but this needs fixing soon
fn monitor_flows(
    poll: &mut Poll,
    flows: &mut HashMap<FlowV4Key, FlowV4>,
    tuns: &mut HashMap<usize, Tun>,
) {
    error!("Total flows {}", flows.len());

    let mut keys = Vec::new();
    for (k, f) in flows.iter_mut() {
        if f.dead_time.elapsed() > Duration::from_secs(f.cleanup_after as u64) {
            if let Some(tx_socket) = tuns.get_mut(&f.tx_socket) {
                flow_close(k, f, &mut tx_socket.tun);
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
                    tx_socket.pending_tx.remove(f.tx_socket);
                    f.pending_tx_qed = false;
                    f.pending_tx = None;
                }
                if f.tx_socket != GWTUN_IDX {
                    // Gateway socket is monitored seperately, if the flow is dead, just
                    // deregister the direct sockets
                    tx_socket
                        .tun
                        .event_register(Token(f.tx_socket), poll, RegType::Dereg)
                        .ok();
                    tuns.remove(&f.tx_socket);
                }
            }
            keys.push(*k);
        }
    }
    for k in keys {
        flows.remove(&k);
    }
    flows.shrink_to_fit();
    tuns.shrink_to_fit();
}

fn close_gateway_flows(flows: &mut HashMap<FlowV4Key, FlowV4>, tun: &mut Tun) {
    match tun.flows {
        TunFlow::OneToMany(ref mut tun_flows) => {
            for (_, k) in tun_flows.iter() {
                if let Some(f) = flows.get_mut(k) {
                    flow_close(k, f, &mut tun.tun);
                    flows.remove(k);
                }
            }
            tun_flows.clear();
        }
        _ => panic!("Expecting hashmap for gateway tunnel"),
    }
}

fn close_direct_flows(flows: &mut HashMap<FlowV4Key, FlowV4>, tuns: &mut HashMap<usize, Tun>) {
    let mut keys = Vec::new();
    for (k, f) in flows.iter_mut() {
        if f.tx_socket != GWTUN_IDX {
            if let Some(tun) = tuns.get_mut(&f.tx_socket) {
                flow_close(k, f, &mut tun.tun);
                tuns.remove(&f.tx_socket);
                keys.push(*k);
            }
        }
    }
    for k in keys {
        flows.remove(&k);
    }
}

fn agent_main_thread(direct: usize, platform: usize) -> std::io::Result<()> {
    #[cfg(target_os = "android")]
    android_logger::init_once(
        Config::default()
            .with_min_level(Level::Info)
            .with_tag("NxtAgentLib"),
    );

    let mut poll = Poll::new()?;
    let mut events = Events::with_capacity(2048);

    let mut agent = AgentInfo::default();
    if direct == 1 {
        DIRECT.store(1, std::sync::atomic::Ordering::Relaxed);
    }
    agent.platform = platform;
    agent.next_tun_idx = TUN_START;

    dummy_onboard(&mut agent);

    let mut flow_ager = Instant::now();
    let mut monitor_ager = Instant::now();
    loop {
        let two_secs = Duration::new(2, 0);
        poll.poll(&mut events, Some(two_secs))?;

        for event in events.iter() {
            match event.token() {
                APPTUN => {
                    if event.is_readable() {
                        apptun_rx(
                            &mut agent.app_tun,
                            &mut agent.flows,
                            &mut agent.app_rx,
                            &mut agent.app_tx,
                            &mut agent.tuns,
                            &mut agent.next_tun_idx,
                            &mut poll,
                            agent.gw_onboarded,
                        );
                        agent
                            .app_tun
                            .tun
                            .event_register(APPTUN, &mut poll, RegType::Rereg)
                            .ok();
                    }
                    if event.is_writable() {
                        agent.app_tun.tx_ready = true;
                    }
                }
                idx => {
                    if let Some(tun) = agent.tuns.get_mut(&idx.0) {
                        if event.is_readable() {
                            gwtun_rx(
                                tun,
                                &mut agent.flows,
                                &mut agent.app_rx,
                                &mut agent.app_tx,
                                &mut poll,
                            );
                        }
                        if event.is_writable() {
                            tun.tx_ready = true;
                            gwtun_tx(tun, &mut agent.flows);
                        }
                    }
                }
            }

            // Note that write-ready is a single shot event and it will continue to be write-ready
            // till we get an will-block return value on attempting some write. So as long as things
            // are write-ready, see if we have any pending data to Tx to the app tunnel or the gateway
            if agent.app_tun.tx_ready {
                apptun_tx(&mut agent.app_tun, &mut agent.app_tx);
            }
        }

        if !agent.gw_onboarded && agent.idp_onboarded {
            agent.gw_onboarded = send_onboard_info(&mut agent.reginfo, &mut agent.gw_tun);
        }

        // Note that we have a poll timeout of two seconds, but packets can keep the loop busy
        // so make sure we monitor only every two secs
        if monitor_ager.elapsed() >= Duration::from_secs(2) {
            monitor_gw(&mut agent, &mut poll);
            monitor_appfd(&mut agent, &mut poll);
            monitor_ager = Instant::now();
        }
        if flow_ager.elapsed() >= Duration::from_secs(30) {
            // Check the flow aging only once every 30 seconds
            monitor_flows(&mut poll, &mut agent.flows, &mut agent.tuns);
            flow_ager = Instant::now();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn agent_init(platform: usize, direct: usize) {
    if INITED.load(std::sync::atomic::Ordering::Relaxed) == 0 {
        error!("Agent init called {:?}", SystemTime::now());
        thread::spawn(move || {
            agent_main_thread(direct, platform).ok();
        });
        INITED.store(1, std::sync::atomic::Ordering::Relaxed);
    }
}

// We EXPECT the fd provied to us to be already non blocking
#[no_mangle]
pub unsafe extern "C" fn agent_on(fd: i32) {
    let old_fd = APPFD.load(std::sync::atomic::Ordering::Relaxed);
    error!("Agent on, old {}, new {}", old_fd, fd);
    APPFD.store(fd, std::sync::atomic::Ordering::Relaxed);
}

#[no_mangle]
pub unsafe extern "C" fn agent_off() {
    let fd = APPFD.load(std::sync::atomic::Ordering::Relaxed);
    error!("Agent off {}", fd);
    APPFD.store(0, std::sync::atomic::Ordering::Relaxed);
}
