use std::sync::Arc;
use deku::bitvec::{bits, BitSlice, BitVec, Msb0};
use deku::prelude::*;
use tokio::net::{TcpListener, TcpSocket, TcpStream};

#[derive(Debug, PartialEq, Eq)]
struct DNSName(String);

impl DekuWrite<Endian> for DNSName {
    fn write(&self, output: &mut BitVec<u8, Msb0>, ctx: Endian) -> Result<(), DekuError> {
        let label = Label::Regular(RegularMsg::Regular(self.0.as_str().as_bytes()));
        label.write(output, ())
    }
}

impl<'a> DekuRead<'a, Endian> for DNSName {
    fn read(mut input: &'a BitSlice<u8, Msb0>, ctx: Endian) -> Result<(&'a BitSlice<u8, Msb0>, Self), DekuError> where Self: Sized {
        let mut decoded = String::new();
        let mut rest1 = input;

        while !input.is_empty() {
            let (remaining, label) = match Label::read(input, ()) {
                Ok((remaining, label)) => (remaining, label),
                Err(err) => return Err(err),
            };

            match label {
                Label::Regular(RegularMsg::End) => break, // End of domain name
                Label::Pointer(offset) => {
                    if offset as usize >= input.len() {
                        return Err(DekuError::Parse("Invalid compression pointer offset".into()));
                    }

                    let (_, label_bytes) = input.split_at(offset as usize * 8);

                    let (rest, current_part) = DNSName::read(label_bytes, ctx)?;
                    decoded.push_str(current_part.0.as_str());
                    rest1 = rest;
                    break; // Pointers should only appear at the end
                }
                Label::Regular(RegularMsg::Regular(label_bytes)) => {
                    let label = String::from_utf8_lossy(&label_bytes);
                    decoded.push_str(&label);
                    decoded.push('.');

                    input = remaining;
                }
            }
        }

        // Remove the trailing period if exists
        if decoded.ends_with('.') {
            decoded.pop();
        }

        Ok((rest1, DNSName(decoded)))
    }
}

fn response_header(id: u16, answers: u16) -> DNSHeader {
    DNSHeader {
        id,       // ID
        qr: 1,            // Response (qr = 1)
        opcode: 0,        // Standard query (opcode = 0)
        aa: 1,            // Not authoritative (aa = 0)
        tc: 0,            // Not truncated (tc = 0)
        rd: 0,            // Recursion desired (rd = 1)
        ra: 0,            // Recursion available (ra = 1)
        z: 0,             // Reserved bits (z = 0)
        rcode: 0,         // No error condition (rcode = 0)
        qdcount: 0,       // Number of questions (qdcount = 0)
        ancount: answers,       // Number of answers (ancount = 1)
        nscount: 0,       // Number of authority resource records (nscount = 0)
        arcount: 0,       // Number of additional resource records (arcount = 0)
    }
}

#[derive(Debug, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
struct DNSQuestion {
    qname: DNSName,
    #[deku(bits = "16")]
    qtype: u16,
    #[deku(bits = "16")]
    qclass: u16,
}


#[derive(Debug, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
struct DNSHeader {
    #[deku(bits = "16")]
    id: u16,
    #[deku(bits = "1")]
    qr: u8,
    #[deku(bits = "4")]
    opcode: u8,
    #[deku(bits = "1")]
    aa: u8,
    #[deku(bits = "1")]
    tc: u8,
    #[deku(bits = "1")]
    rd: u8,
    #[deku(bits = "1")]
    ra: u8,
    #[deku(bits = "3")]
    z: u8,
    #[deku(bits = "4")]
    rcode: u8,
    #[deku(bits = "16")]
    qdcount: u16,
    #[deku(bits = "16")]
    ancount: u16,
    #[deku(bits = "16")]
    nscount: u16,
    #[deku(bits = "16")]
    arcount: u16,
}


#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(type = "u8", ctx = "endian: Endian")]
enum RegularMsg<'a> {
    #[deku(id = "0")]
    End,
    #[deku(id_pat = "_")]
    Regular(#[deku(
    until = "|v: &u8| *v == 0"
    )] &'a [u8]),
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
struct Question {
    header: DNSHeader,
    question: DNSQuestion,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
struct Response {
    header: DNSHeader,
    question: DNSQuestion,
    answer: DNSRecord,
}


#[derive(Debug, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(endian = "big")]
struct DNSRecord {
    name: DNSName,
    #[deku(bits = "16")]
    rtype: u16,
    #[deku(bits = "16", assert_eq = "1")]
    class: u16,
    #[deku(bits = "32")]
    ttl: u32,

    #[deku(bits = "16")]
    rdlength: u16,

    #[deku(count = "rdlength")]
    rdata: Vec<u8>,
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(type = "u8", bits = "2", endian = "big")]
enum Label<'a> {
    #[deku(id = "0b11")]
    Pointer(#[deku(bits = "6", endian = "big")] u8),
    #[deku(id_pat = "_")]
    Regular(RegularMsg<'a>),
}

async fn handle_dns_packet(socket: &mut TcpStream, data: &[u8]) {
    // Parse the DNS question from the packet
    let bitslice = BitSlice::from_slice(data);
    let dns_question = match Question::read(bitslice, ()) {
        Ok((_, dns_question)) => dns_question,
        Err(err) => {
            eprintln!("Failed to parse DNS question: {:?}", err);
            return;
        }
    };

    println!("{:?}", dns_question);


    let response = Response {
        header: response_header(dns_question.header.id, 1),
        question: dns_question.question,
        answer: DNSRecord {
            name: DNSName("example.com".to_string()),
            rtype: 1,
            class: 1,
            ttl: 0,
            rdlength: 4,
            rdata: vec![127, 0, 0, 1],
        },
    };
    // ... Additional logic here based on the DNS question

    // Example response:
    let response = response.to_bytes().unwrap();
    println!("{:?}", response);

    // Send the response back to the client
    if let Err(err) = socket.write(&response).await {
        eprintln!("Failed to send DNS response: {:?}", err);
    }
}

async fn run_dns_server() -> Result<(), Box<dyn std::error::Error>> {
    let mut listener = TcpListener::bind("127.0.0.1:53").await.unwrap();
    println!("DNS server listening on: {:?}", listener.local_addr());

    let mut buf = Vec::new();

    loop {
        let (mut stream, unused) = listener.accept().await?;
        println!("New connection: {}", stream.peer_addr().unwrap());
        stream.read_to_end(&mut buf).await?;
        println!("Read to end!");
        handle_dns_packet(&mut stream, &buf).await;
    }

    Ok(())

    // loop {
    //     let (size, addr) = socket.recv_from(&mut buf).await?;
    //
    //     let socket1 = socket.clone();
    //     tokio::spawn(async move {
    //         handle_dns_packet(&socket1, &buf[..size], addr).await;
    //     });
    //
    //     // Uncomment the following line to handle packets sequentially instead of concurrently
    //     // handle_dns_packet(&socket, &buf[..size], addr).await;
    // }
}

#[tokio::main]
async fn main() {
    if let Err(err) = run_dns_server().await {
        eprintln!("DNS server error: {:?}", err);
    }
}


use deku::prelude::*;
use deku::{DekuContainerWrite, DekuWrite};
use deku::bitvec::bitvec;
use deku::ctx::Endian;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::RegularMsg::Regular;


fn main1() {

    // 31?
    let data: Vec<u8> = vec![
        0b11_100_110,
        0b00_000_000 | 'C' as u8, 0b00_000_000 | 'A' as u8, 0b00_000_000 | 'B' as u8, 0, 0,
        0b11_010_011,
        0b00_000_000 | 'D' as u8, 0b00_000_000 | 'E' as u8, 0b00_000_000 | 'F' as u8, 0, 0];

    println!("{:?}", data.as_slice());
    let (rest, value0) = Label::from_bytes((data.as_ref(), 0)).unwrap();
    println!("{:?}", rest);

    println!("{:?}", value0);

    let (rest, value1) = Label::from_bytes(rest).unwrap();
    println!("{:?}", value1);
    println!("{:?}", rest);


    let (rest, value2) = Label::from_bytes(rest).unwrap();
    println!("{:?}", value2);

    println!("{:?}", rest);

    let (rest, value3) = Label::from_bytes(rest).unwrap();
    println!("{:?}", value3);

    println!("{:?}", rest);


    let (rest, value4) = Label::from_bytes(rest).unwrap();
    println!("{:?}", value4);

    let (rest, value5) = Label::from_bytes(rest).unwrap();
    println!("{:?}", value5);

    let total = vec![value0, value1, value2, value3, value4, value5];

    let mut output = bitvec![u8, Msb0;];
    total.write(&mut output, ()).unwrap();

    output.force_align();
    let output = output.into_vec();

    println!("{:?}", output);
}