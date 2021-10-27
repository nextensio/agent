// The code here is from https://github.com/EmilHernvall/dnsguide sample5.rs

use log::error;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Instant;

type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

pub struct BytePacketBuffer<'a> {
    pub buf: &'a mut [u8],
    pub pos: usize,
}

impl<'a> BytePacketBuffer<'a> {
    pub fn new(buf: &'a mut [u8]) -> BytePacketBuffer<'a> {
        BytePacketBuffer { buf, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    fn step(&mut self, steps: usize) {
        self.pos += steps;
    }

    fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn read(&mut self) -> Result<u8> {
        if self.pos >= 512 || self.pos >= self.buf.len() {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn get(&mut self, pos: usize) -> Result<u8> {
        if pos >= 512 || pos >= self.buf.len() {
            return Err("End of buffer".into());
        }
        Ok(self.buf[pos])
    }

    fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 || (start + len) >= self.buf.len() {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len as usize])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | (self.read()? as u32);

        Ok(res)
    }

    fn read_qname(&mut self, outstr: &mut String) -> Result<()> {
        let mut pos = self.pos();
        let mut jumped = false;

        let mut delim = "";
        let max_jumps = 5;
        let mut jumps_performed = 0;
        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            let len = self.get(pos)?;

            // A two byte sequence, where the two highest bits of the first byte is
            // set, represents a offset relative to the start of the buffer. We
            // handle this by jumping to the offset, setting a flag to indicate
            // that we shouldn't update the shared buffer position once done.
            if (len & 0xC0) == 0xC0 {
                // When a jump is performed, we only modify the shared buffer
                // position once, and avoid making the change later on.
                if !jumped {
                    self.seek(pos + 2);
                }

                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;
                jumped = true;
                jumps_performed += 1;
                continue;
            }

            pos += 1;

            // Names are terminated by an empty label of length 0
            if len == 0 {
                break;
            }

            outstr.push_str(delim);

            let str_buffer = self.get_range(pos, len as usize)?;
            outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

            delim = ".";

            pos += len as usize;
        }

        if !jumped {
            self.seek(pos);
        }

        Ok(())
    }

    fn write(&mut self, val: u8) -> Result<()> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        self.buf[self.pos] = val;
        self.pos += 1;
        Ok(())
    }

    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(val)?;

        Ok(())
    }

    fn write_u16(&mut self, val: u16) -> Result<()> {
        self.write((val >> 8) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_u32(&mut self, val: u32) -> Result<()> {
        self.write(((val >> 24) & 0xFF) as u8)?;
        self.write(((val >> 16) & 0xFF) as u8)?;
        self.write(((val >> 8) & 0xFF) as u8)?;
        self.write((val & 0xFF) as u8)?;

        Ok(())
    }

    fn write_qname(&mut self, qname: &str) -> Result<()> {
        for label in qname.split('.') {
            let len = label.len();
            if len > 0x34 {
                return Err("Single label exceeds 63 characters of length".into());
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }

    fn set(&mut self, pos: usize, val: u8) {
        self.buf[pos] = val;
    }

    fn set_u16(&mut self, pos: usize, val: u16) {
        self.set(pos, (val >> 8) as u8);
        self.set(pos + 1, (val & 0xFF) as u8);
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    Noerror = 0,
    Formerr = 1,
    Servfail = 2,
    Nxdomain = 3,
    Notimp = 4,
    Refused = 5,
}

impl ResultCode {
    pub fn from_num(num: u8) -> ResultCode {
        match num {
            1 => ResultCode::Formerr,
            2 => ResultCode::Servfail,
            3 => ResultCode::Nxdomain,
            4 => ResultCode::Notimp,
            5 => ResultCode::Refused,
            0 => ResultCode::Noerror,
            _ => ResultCode::Noerror,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::Noerror,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;
        self.recursion_desired = (a & (1 << 0)) > 0;
        self.truncated_message = (a & (1 << 1)) > 0;
        self.authoritative_answer = (a & (1 << 2)) > 0;
        self.opcode = (a >> 3) & 0x0F;
        self.response = (a & (1 << 7)) > 0;

        self.rescode = ResultCode::from_num(b & 0x0F);
        self.checking_disabled = (b & (1 << 4)) > 0;
        self.authed_data = (b & (1 << 5)) > 0;
        self.z = (b & (1 << 6)) > 0;
        self.recursion_available = (b & (1 << 7)) > 0;

        self.questions = buffer.read_u16()?;
        self.answers = buffer.read_u16()?;
        self.authoritative_entries = buffer.read_u16()?;
        self.resource_entries = buffer.read_u16()?;

        // Return the constant header size
        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | (self.opcode << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.rescode as u8)
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    Unknown(u16),
    A,     // 1
    Ns,    // 2
    Cname, // 5
    Mx,    // 15
    Aaaa,  // 28
}

impl QueryType {
    pub fn get_number(&self) -> u16 {
        match *self {
            QueryType::Unknown(x) => x,
            QueryType::A => 1,
            QueryType::Ns => 2,
            QueryType::Cname => 5,
            QueryType::Mx => 15,
            QueryType::Aaaa => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::Ns,
            5 => QueryType::Cname,
            15 => QueryType::Mx,
            28 => QueryType::Aaaa,
            _ => QueryType::Unknown(num),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name, qtype }
    }

    pub fn read(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.read_qname(&mut self.name)?;
        self.qtype = QueryType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

        Ok(())
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<()> {
        buffer.write_qname(&self.name)?;

        let typenum = self.qtype.get_number();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    Unknown {
        domain: String,
        qtype: u16,
        data_len: u16,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    Ns {
        domain: String,
        host: String,
        ttl: u32,
    }, // 2
    Cname {
        domain: String,
        host: String,
        ttl: u32,
    }, // 5
    Mx {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    }, // 15
    Aaaa {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    }, // 28
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord> {
        let mut domain = String::new();
        buffer.read_qname(&mut domain)?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()?;

        match qtype {
            QueryType::A => {
                let raw_addr = buffer.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    (raw_addr & 0xFF) as u8,
                );

                Ok(DnsRecord::A { domain, addr, ttl })
            }
            QueryType::Aaaa => {
                let raw_addr1 = buffer.read_u32()?;
                let raw_addr2 = buffer.read_u32()?;
                let raw_addr3 = buffer.read_u32()?;
                let raw_addr4 = buffer.read_u32()?;
                let addr = Ipv6Addr::new(
                    ((raw_addr1 >> 16) & 0xFFFF) as u16,
                    (raw_addr1 & 0xFFFF) as u16,
                    ((raw_addr2 >> 16) & 0xFFFF) as u16,
                    (raw_addr2 & 0xFFFF) as u16,
                    ((raw_addr3 >> 16) & 0xFFFF) as u16,
                    (raw_addr3 & 0xFFFF) as u16,
                    ((raw_addr4 >> 16) & 0xFFFF) as u16,
                    (raw_addr4 & 0xFFFF) as u16,
                );

                Ok(DnsRecord::Aaaa { domain, addr, ttl })
            }
            QueryType::Ns => {
                let mut ns = String::new();
                buffer.read_qname(&mut ns)?;

                Ok(DnsRecord::Ns {
                    domain,
                    host: ns,
                    ttl,
                })
            }
            QueryType::Cname => {
                let mut cname = String::new();
                buffer.read_qname(&mut cname)?;

                Ok(DnsRecord::Cname {
                    domain,
                    host: cname,
                    ttl,
                })
            }
            QueryType::Mx => {
                let priority = buffer.read_u16()?;
                let mut mx = String::new();
                buffer.read_qname(&mut mx)?;

                Ok(DnsRecord::Mx {
                    domain,
                    priority,
                    host: mx,
                    ttl,
                })
            }
            QueryType::Unknown(_) => {
                buffer.step(data_len as usize);

                Ok(DnsRecord::Unknown {
                    domain,
                    qtype: qtype_num,
                    data_len,
                    ttl,
                })
            }
        }
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.get_number())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DnsRecord::Ns {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::Ns.get_number())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16);
            }
            DnsRecord::Cname {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::Cname.get_number())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16);
            }
            DnsRecord::Mx {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::Mx.get_number())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                let pos = buffer.pos();
                buffer.write_u16(0)?;

                buffer.write_u16(priority)?;
                buffer.write_qname(host)?;

                let size = buffer.pos() - (pos + 2);
                buffer.set_u16(pos, size as u16);
            }
            DnsRecord::Aaaa {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::Aaaa.get_number())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::Unknown { .. } => {
                println!("Skipping record: {:?}", self);
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket> {
        let mut result = DnsPacket::new();
        result.header.read(buffer)?;

        for _ in 0..result.header.questions {
            let mut question = DnsQuestion::new("".to_string(), QueryType::Unknown(0));
            question.read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<()> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }
}

#[allow(dead_code)]
pub fn print_responses(req_buffer: &mut BytePacketBuffer) {
    let mut request;
    if let Ok(r) = DnsPacket::from_buffer(req_buffer) {
        request = r;
    } else {
        return;
    }
    loop {
        if let Some(ans) = request.answers.pop() {
            match ans {
                DnsRecord::A { domain, addr, ttl } => {
                    error!("DNS answer A {} {} {}", domain, addr, ttl);
                }
                DnsRecord::Aaaa { domain, addr, ttl } => {
                    error!("DNS answer Aaaa {} {} {}", domain, addr, ttl);
                }
                DnsRecord::Ns { domain, host, ttl } => {
                    error!("DNS answer Ns {} {} {}", domain, host, ttl);
                }
                DnsRecord::Cname { domain, host, ttl } => {
                    error!("DNS answer Cname {} {} {}", domain, host, ttl);
                }
                DnsRecord::Mx {
                    domain,
                    priority,
                    host,
                    ttl,
                } => {
                    error!("DNS answer Mx {} {} {} {}", domain, priority, host, ttl);
                }
                DnsRecord::Unknown {
                    domain,
                    qtype,
                    data_len,
                    ttl,
                } => error!("Unknown response {} {} {} {}", domain, qtype, data_len, ttl),
            }
        } else {
            return;
        }
    }
}

pub fn monitor_dns(nameip: &mut super::NameIp) {
    let mut aged = vec![];
    for (k, v) in nameip.dns.iter() {
        if v.alloc_time.elapsed().as_secs() >= super::DNS_TTL as u64 {
            aged.push(k.clone());
            nameip.rdns.remove(&v.ip);
        }
    }
    for a in aged {
        nameip.dns.remove(&a);
    }
}

fn get_dns(rdns: &HashMap<Ipv4Addr, super::Rdns>, start: &Instant) -> Ipv4Addr {
    // Poor man's random - I DONT want to pull in the rand crate just
    // for this, the rand crate also pulls in humongous crates like serde
    let mut count = 0;
    loop {
        // get a random IP address 100.64.x.y (CG-NAT range)
        let elapsed = start.elapsed().as_nanos();
        let val1 = (elapsed & 0xFFFF) as u16;
        let val2 = ((elapsed >> 16) & 0xFFFF) as u16;
        let val3 = ((elapsed >> 32) & 0xFFFF) as u16;
        let val4 = ((elapsed >> 48) & 0xFFFF) as u16;
        let val5 = ((elapsed >> 64) & 0xFFFF) as u16;
        let val6 = ((elapsed >> 80) & 0xFFFF) as u16;
        let val7 = ((elapsed >> 96) & 0xFFFF) as u16;
        let val8 = ((elapsed >> 112) & 0xFFFF) as u16;
        let val = val1 ^ val2 ^ val3 ^ val4 ^ val5 ^ val6 ^ val7 ^ val8;
        // 100.64.1.1, 100.64.1.2, 100.64.1.3 are usually used by android/ios/windows
        // etc.. as the tunnel IP, tunnel next-hop and the dns server IP
        if val == 0 || val == 0x0101 || val == 0x0102 || val == 0x0103 {
            count += 1;
            continue;
        }
        let ip = Ipv4Addr::new(100, 64, (val >> 8) as u8, (val & 0xFF) as u8);
        if rdns.contains_key(&ip) {
            count += 1;
            continue;
        }
        if count != 0 {
            error!("DNS looped {} times", count);
        }
        return ip;
    }
}

pub fn handle_nextensio_query(
    nameip: &mut super::NameIp,
    domains: &[super::Domain],
    req_buffer: &mut BytePacketBuffer,
    res_buffer: &mut BytePacketBuffer,
) -> bool {
    let mut request;
    if let Ok(r) = DnsPacket::from_buffer(req_buffer) {
        request = r;
    } else {
        return false;
    }

    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_desired = true;
    packet.header.recursion_available = true;
    packet.header.response = true;

    if let Some(question) = request.questions.pop() {
        let mut found = false;
        for d in domains.iter() {
            if question.name.contains(&d.name) {
                found = true;
                break;
            }
        }
        if found {
            let addr;
            if let Some(d) = nameip.dns.get_mut(&question.name) {
                addr = d.ip;
                d.alloc_time = Instant::now();
            } else {
                addr = get_dns(&nameip.rdns, &nameip.start);
                nameip.rdns.insert(
                    addr,
                    super::Rdns {
                        fqdn: question.name.clone(),
                    },
                );
                nameip.dns.insert(
                    question.name.clone(),
                    super::Dns {
                        ip: addr,
                        alloc_time: Instant::now(),
                    },
                );
            }
            let ans = DnsRecord::A {
                domain: question.name.clone(),
                addr,
                ttl: super::DNS_TTL,
            };
            packet.questions.push(question);
            packet.header.rescode = ResultCode::Noerror;
            packet.answers.push(ans);
        } else {
            return false;
        }
    } else {
        return false;
    }

    if packet.write(res_buffer).is_err() {
        return false;
    }

    true
}
