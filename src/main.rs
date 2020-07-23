#![allow(unused_variables, dead_code)]
use dnsserver::{BytePacketBuffer, DnsPacket, DnsQuestion, QueryType, ResultCode};
use std::{io::Error, net::UdpSocket};
fn lookup(qname: &str, qtype: QueryType, server: (&str, u16)) -> Result<DnsPacket, Error> {
    let mut packet = DnsPacket::new();
    packet.header.id = 6666;
    packet.header.recursion_desired = true;
    packet.header.questions = 1;
    packet
        .questions
        .push(DnsQuestion::new(qname.to_string(), qtype));

    let mut req_packet = BytePacketBuffer::new();
    packet.write(&mut req_packet)?;

    let socket = UdpSocket::bind(("0.0.0.0", 43210)).unwrap();
    socket.send_to(&req_packet.buf, server)?;

    let mut recv_packet = BytePacketBuffer::new();
    socket.recv_from(&mut recv_packet.buf).unwrap();

    Ok(DnsPacket::from_buffer(&mut recv_packet)?)
}

fn recursive_lookup(qname: &str, qtype: QueryType) -> Result<DnsPacket, Error> {
    let mut ns = "198.41.0.4".to_string();

    loop {
        println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);

        let ns_copy = ns.clone();

        let server = (ns_copy.as_str(), 53);
        let response = lookup(qname, qtype.clone(), server)?;

        if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
            return Ok(response.clone());
        }

        if response.header.rescode == ResultCode::NXDOMAIN {
            return Ok(response.clone());
        }

        if let Some(new_ns) = response.get_resolved_ns(qname) {
            ns = new_ns.clone();

            continue;
        }

        let new_ns_name = match response.get_unresolved_ns(qname) {
            Some(x) => x,
            None => return Ok(response.clone()),
        };

        let recursive_response = recursive_lookup(&new_ns_name, QueryType::A)?;

        if let Some(new_ns) = recursive_response.get_random_a() {
            ns = new_ns.clone();
        } else {
            return Ok(response.clone());
        }
    }
}
fn main() {
    let server = ("192.203.230.10", 53);
    let socket = UdpSocket::bind(("0.0.0.0", 1053)).unwrap();

    loop {
        let mut req_buffer = BytePacketBuffer::new();
        let (_, src) = match socket.recv_from(&mut req_buffer.buf) {
            Ok(x) => x,
            Err(e) => {
                println!("Failed to read from UDP socket {}", e);
                continue;
            }
        };

        let request = match DnsPacket::from_buffer(&mut req_buffer) {
            Ok(x) => x,
            Err(e) => {
                println!("Failed to parse UDP query packet {}", e);
                continue;
            }
        };

        let mut packet = DnsPacket::new();
        packet.header.id = request.header.id;
        packet.header.recursion_desired = true;
        packet.header.recursion_available = true;
        packet.header.response = true;

        if request.questions.is_empty() {
            packet.header.rescode = ResultCode::FORMERR;
        } else {
            let question = &request.questions[0];
            println!("Received request {:?}", question);

            if let Ok(response) = recursive_lookup(&question.name, question.qtype) {
                packet.questions.push(question.clone());
                packet.header.rescode = response.header.rescode;

                for answer in response.answers {
                    println!("Answer: {:?}", answer);
                    packet.answers.push(answer);
                }

                for authority in response.authorities {
                    println!("Authority: {:?}", authority);
                    packet.authorities.push(authority);
                }

                for resource in response.resources {
                    println!("Resource: {:?}", resource);
                    packet.resources.push(resource);
                }
            } else {
                packet.header.rescode = ResultCode::SERVFAIL;
            }

            let mut res_buffer = BytePacketBuffer::new();
            match packet.write(&mut res_buffer) {
                Ok(_) => {}
                Err(e) => {
                    println!("Failed to encode UDP response packet {:?}", e);
                    continue;
                }
            }

            let len = res_buffer.pos();
            let data = match res_buffer.get_range(0, len) {
                Ok(x) => x,
                Err(e) => {
                    println!("Failed to retrieve response buffer {:?}", e);
                    continue;
                }
            };

            match socket.send_to(data, src) {
                Ok(_) => {}
                Err(e) => {
                    println!("Failed to send response buffer {}", e);
                    continue;
                }
            }
        }
    }
}
