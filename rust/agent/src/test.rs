use super::*;
use crate::Dummy;

#[test]
fn pkt_parse_two_bufs() {
    pkt_parse(64 * 1024);
}

#[test]
fn pkt_parse_one_bufs() {
    pkt_parse(2 * 1024);
}

fn pkt_parse(bytes: usize) {
    let mut agent = AgentInfo::default();
    agent_init_pools(&mut agent, 1500, 0);

    let key = FlowV4Key {
        sip: 0x01010101,
        dip: "2.2.2.2".to_string(),
        sport: 32145,
        dport: 443,
        proto: common::TCP,
    };

    let flow = FlowV4 {
        rx_socket: Box::new(Dummy::default()),
        rx_socket_idx: 0,
        rx_stream: None,
        tx_stream: 0,
        tx_socket: UNUSED_IDX,
        pending_tx: None,
        pending_rx: VecDeque::with_capacity(1),
        last_rdwr: Instant::now(),
        creation_instant: Instant::now(),
        cleanup_after: CLEANUP_TCP_HALFOPEN,
        dialled: false,
        dead: false,
        pending_tx_qed: false,
        service: "".to_string(),
        dest_agent: "".to_string(),
        parse_pending: None,
        trace_request: true,
    };

    let mut pending = pool_get(agent.ext.pkt_pool.clone()).unwrap();
    pending.clear();

    let mut http = r#"GET /hello.htm HTTP/1.1
User-Agent: Mozilla/4.0 (compatible; MSIE5.01; Windows NT)
Accept-Language: en-us
Accept-Encoding: gzip, deflate
Connection: Keep-Alive
Host: www.tutorialspoint.com
X-Long-Header: 
"#
    .to_string();

    for _ in 0..bytes {
        http.push_str("a");
    }
    http.push_str("\n\n");
    let http_u8 = http.as_bytes();
    let mut next = 0;
    let mut t = pool_get(agent.ext.tcp_pool.clone()).unwrap();
    t.clear();
    let mut v: Vec<Reusable<Vec<u8>>> = vec![];

    loop {
        if next == http_u8.len() {
            v.push(t);
            break;
        }
        if t.len() == t.capacity() {
            v.push(t);
            t = pool_get(agent.ext.tcp_pool.clone()).unwrap();
            t.clear();
        }
        let rem = http_u8[next..].len();
        let cp = std::cmp::min(rem, t.capacity() - t.len());
        t.extend_from_slice(&http_u8[next..next + cp]);
        next += cp;
    }
    println!("pre-parse: vec len {}", v.len());
    for i in 0..v.len() {
        println!("pre-parse: index {}, len {}", i, v[i].len());
    }
    let tx = NxtBufs {
        hdr: None,
        bufs: v,
        headroom: 0,
    };
    let (out, err) = parse_copy(&agent.ext.tcp_pool, &mut pending, tx);
    println!(
        "post-parse: pending len {}, out len {}",
        pending.len(),
        out.len()
    );
    if err {
        println!("post-parse: error {}", err);
    }
    for i in 0..out.len() {
        println!("post-parse: index {}, len {}", i, out[i].len());
    }
    let (_, _, service) = parse_host(&pending[0..]);
    println!("Service is {}", service);
}
