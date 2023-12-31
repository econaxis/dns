use deku::{ctx::Endian, prelude::*};

use deku::bitvec::{BitSlice, BitVec, Msb0};

#[derive(PartialEq, DekuRead, DekuWrite, Clone, Debug, Eq)]
#[deku(bits = "4", type = "u8")]
pub enum Rcode {
    /*
        DNS Return Code	DNS Return Message	Description
    RCODE:0	NOERROR	DNS Query completed successfully
    RCODE:1	FORMERR	DNS Query Format Error
    RCODE:2	SERVFAIL	Server failed to complete the DNS request
    RCODE:3	NXDOMAIN	Domain name does not exist
    RCODE:4	NOTIMP	Function not implemented
    RCODE:5	REFUSED	The server refused to answer for the query
    RCODE:6	YXDOMAIN	Name that should not exist, does exist
    RCODE:7	XRRSET	RRset that should not exist, does exist
    RCODE:8	NOTAUTH	Server not authoritative for the zone
    RCODE:9	NOTZONE
    Name not in zone
         */
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NxDomain = 3,
    NotImplemented = 4,
    Refused = 5,
    YXDomain = 6,
    YXRRSet = 7,
    NotAuth = 8,
    NotZone = 9,
}

pub fn response_header(id: u16, answers: usize, authorities: usize, additionals: usize, is_tcp: bool, truncated: bool, rcode: Rcode) -> DNSHeader {
    DNSHeader {
        tcp_header_field: if is_tcp { TcpHeaderField(Some(0)) } else { TcpHeaderField(None) },
        id,                          // ID
        qr: 1,                       // Response (qr = 1)
        opcode: 0,                   // Standard query (opcode = 0)
        aa: 1,                       // Not authoritative (aa = 0)
        tc: u8::from(truncated),     // Not truncated (tc = 0)
        rd: 0,                       // Recursion desired (rd = 0)
        ra: 0,                       // Recursion available (ra = 0)
        z: 0,                        // Reserved bits (z = 0)
        rcode,                       // No error condition (rcode = 0)
        qdcount: 1,                  // Number of questions (qdcount = 0)
        ancount: answers as u16,     // Number of answers (ancount = 1)
        nscount: authorities as u16, // Number of authority resource records (nscount = 0)
        arcount: additionals as u16, // Number of additional resource records (arcount = 0)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct TcpHeaderField(Option<u16>);

impl TcpHeaderField {
    fn set(&mut self, value: u16) {
        if let Some(a) = self.0.as_mut() {
            *a = value;
        }
    }

    fn is_tcp(&self) -> bool {
        self.0.is_some()
    }
}

impl DekuWrite<(Endian, bool)> for TcpHeaderField {
    fn write(&self, output: &mut BitVec<u8, Msb0>, is_tcp: (Endian, bool)) -> Result<(), DekuError> {
        if is_tcp.1 {
            self.0.unwrap().write(output, is_tcp.0)?;
        }
        Ok(())
    }
}

impl DekuRead<'_, (Endian, bool)> for TcpHeaderField {
    fn read(input: &BitSlice<u8, Msb0>, is_tcp: (Endian, bool)) -> Result<(&BitSlice<u8, Msb0>, Self), DekuError> {
        if is_tcp.1 {
            let (input, value) = u16::read(input, is_tcp.0)?;
            Ok((input, TcpHeaderField(Some(value))))
        } else {
            Ok((input, TcpHeaderField(None)))
        }
    }
}

#[derive(Debug, PartialEq, Eq, DekuRead, DekuWrite)]
#[deku(endian = "big", ctx = "is_tcp: bool")]
pub struct DNSHeader {
    #[deku(ctx = "is_tcp")]
    tcp_header_field: TcpHeaderField,
    #[deku(bits = "16")]
    pub(crate) id: u16,
    #[deku(bits = "1")]
    qr: u8,
    #[deku(bits = "4")]
    opcode: u8,
    #[deku(bits = "1")]
    aa: u8,
    #[deku(bits = "1")]
    pub(crate) tc: u8,
    #[deku(bits = "1")]
    rd: u8,
    #[deku(bits = "1")]
    ra: u8,
    #[deku(bits = "3")]
    z: u8,
    #[deku(endian = "")]
    pub rcode: Rcode,
    #[deku(bits = "16")]
    qdcount: u16,
    #[deku(bits = "16")]
    pub(crate) ancount: u16,

    // Authority count
    #[deku(bits = "16")]
    pub(crate) nscount: u16,

    // Additional information count
    #[deku(bits = "16")]
    pub(crate) arcount: u16,
}

impl DNSHeader {
    pub(crate) fn update_from_total_msg_len(&mut self, total_msg_len: u16) -> bool {
        let mut updated = false;

        if total_msg_len > TRUNCATE_BYTES && self.tc == 0 && !self.tcp_header_field.is_tcp() {
            self.tc = 1;
            updated = true;
        }

        if self.tcp_header_field.is_tcp() {
            self.tcp_header_field.set(total_msg_len);
            updated = true;
        }

        updated
    }

    pub(crate) fn message_len_offset(&self) -> usize {
        if self.tcp_header_field.0.is_some() {
            2
        } else {
            0
        }
    }
}

const TRUNCATE_BYTES: u16 = 512;
