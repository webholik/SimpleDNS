#![allow(unused_variables, dead_code)]
use dnsserver::{BytePacketBuffer, DnsPacket, DnsQuestion, QueryType};
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
fn main() {
    let qname = "google.com";
    let qtype = QueryType::MX;

    let server = ("8.8.8.8", 53);

    let res_packet = lookup(qname, qtype, server).unwrap();
    println!("{:?}", res_packet.header);

    for q in res_packet.questions {
        println!("{:?}", q);
    }
    for rec in res_packet.answers {
        println!("{:?}", rec);
    }
    for rec in res_packet.authorities {
        println!("{:?}", rec);
    }
    for rec in res_packet.resources {
        println!("{:?}", rec);
    }
}
