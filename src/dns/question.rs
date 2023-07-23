use deku::{
    ctx::Endian,
    prelude::*,
};

use crate::dns::{compression::CompressedRef, header::DNSHeader, name::DNSName, record::VecDNSRecord, rtypes::RType};

#[derive(Debug, PartialEq, Eq, DekuRead, DekuWrite, Clone)]
#[deku(endian = "big", ctx = "compressed: CompressedRef")]
pub struct DNSQuestion {
    #[deku(reader = "DNSName::read(deku::input_bits, (Endian::Big, deku::byte_offset, compressed))")]
    #[deku(writer = "DNSName::write(&self.qname, deku::output, (Endian::Big, deku::byte_offset, compressed, self.qtype, true).into())")]
    pub(crate) qname: DNSName,
    pub(crate) qtype: RType,
    #[deku(bits = "16")]
    qclass: u16,
}

#[derive(Debug, PartialEq, DekuRead)]
#[deku(ctx = "is_tcp: bool")]
pub struct Question {
    #[deku(skip)]
    #[deku(default = "CompressedRef::new(is_tcp)")]
    compress: CompressedRef,

    #[deku(ctx = "is_tcp")]
    pub(crate) header: DNSHeader,
    #[deku(ctx = "Clone::clone(compress)")]
    pub(crate) question: DNSQuestion,

    #[deku(ctx = "Clone::clone(compress), header.ancount")]
    answer: VecDNSRecord,
    #[deku(ctx = "Clone::clone(compress), header.nscount")]
    authority: VecDNSRecord,
    #[deku(ctx = "Clone::clone(compress), header.arcount")]
    additional: VecDNSRecord,
}
