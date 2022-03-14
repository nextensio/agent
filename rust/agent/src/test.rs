use super::*;

fn pkt_parse(headroom: usize, bytes: usize, pendsz: usize, outlen: Vec<usize>) {
    let mut agent = AgentInfo::default();
    agent_init_pools(&mut agent, 1500, 0);

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
    let zero = vec![0; headroom];
    t.extend_from_slice(&zero[..]);

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
        headroom,
    };
    let (out, err) = parse_copy(&agent.ext.tcp_pool, &mut pending, tx);
    println!(
        "post-parse: pending len {}, out len {} ",
        pending.len(),
        out.len()
    );

    assert!(pendsz == pending.len());
    assert!(outlen.len() == out.len());

    if err {
        println!("post-parse: error {}", err);
    }
    for i in 0..out.len() {
        assert!(out[i].len() == outlen[i]);
        println!("post-parse: index {}, len {}", i, out[i].len());
    }
    let (_, _, service) = parse_host(&pending[0..]);
    println!("Service is {}", service);
    assert!(service == "www.tutorialspoint.com");
}

#[test]
fn pkt_parse_zero_bufs() {
    let v = vec![];
    pkt_parse(0, 1024, 1231, v);
}

#[test]
fn pkt_parse_one_bufs() {
    let v = vec![207];
    pkt_parse(0, 2 * 1024, 2048, v);
}

#[test]
fn pkt_parse_two_bufs() {
    let v = vec![63488, 207];
    pkt_parse(0, 64 * 1024, 2048, v);
}

#[test]
fn pkt_parse_three_bufs() {
    let v = vec![63488, 64 * 1024, 207];
    pkt_parse(0, 2 * 64 * 1024, 2048, v);
}
