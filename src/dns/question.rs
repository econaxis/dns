use deku::ctx::Endian;
use deku::prelude::*;

use crate::dns::compression::CompressedRef;
use crate::dns::header::DNSHeader;
use crate::dns::name::DNSName;
use crate::dns::record::VecDNSRecord;
use crate::dns::rtypes::Class;

#[derive(Debug, PartialEq, Eq, DekuRead, DekuWrite, Clone)]
#[deku(endian = "big", ctx = "compressed: CompressedRef")]
pub struct DNSQuestion {
    #[deku(reader = "DNSName::read(deku::input_bits, (Endian::Big, deku::byte_offset, compressed))")]
    #[deku(writer = "DNSName::write(&self.qname, deku::output, (Endian::Big, deku::byte_offset, compressed, self.qtype))")]
    pub(crate) qname: DNSName,
    qtype: Class,
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
