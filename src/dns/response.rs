use deku::ctx::Endian;
use deku::prelude::*;

use crate::dns::compression::CompressedRef;
use crate::dns::header;
use crate::dns::header::DNSHeader;
use crate::dns::record::{DNSRecord, VecDNSRecord};
use crate::dns::question::DNSQuestion;
use crate::records::{Records, ResponseSection};

#[derive(Debug, PartialEq, DekuWrite)]
#[deku(ctx = "is_tcp: bool")]
pub struct Response {
    #[deku(skip)]
    compress: CompressedRef,
    #[deku(ctx = "is_tcp")]
    pub(crate) header: DNSHeader,
    #[deku(ctx = "Clone::clone(compress)")]
    question: DNSQuestion,

    #[deku(ctx = "Clone::clone(compress), header.ancount")]
    answer: VecDNSRecord,
    #[deku(ctx = "Clone::clone(compress), header.nscount")]
    authority: VecDNSRecord,
    #[deku(ctx = "Clone::clone(compress), header.arcount")]
    additional: VecDNSRecord,
}


impl Response {
    pub(crate) fn clear(&self) {
        let h = self.compress.pointers.write();
        h.unwrap().clear();
    }
    pub(crate) fn build_from_record_iter<'a>(id: u16, question: DNSQuestion, records: &Records, tcp: bool) -> Response {
        let mut answer = Vec::new();
        let mut authority = Vec::new();
        let mut additional = Vec::new();

        for record in records.query(&question.qname) {
            match record.section {
                ResponseSection::Answer => answer.push(record.record.clone()),
                ResponseSection::Authority => authority.push(record.record.clone()),
                ResponseSection::Additional => additional.push(record.record.clone()),
            }
        };

        for record in &authority {
            additional.extend(records.additional_section(&record.rdata.try_get_name().unwrap()).map(|r| r.record.clone()));
        }

        Response::new(id, question, answer, authority, additional, tcp)
    }
    fn new(id: u16, question: DNSQuestion, answer: Vec<DNSRecord>, authority: Vec<DNSRecord>, additional: Vec<DNSRecord>, tcp: bool) -> Response {
        Response {
            compress: CompressedRef::new(tcp),
            header: header::response_header(id, answer.len(), authority.len(), additional.len(), tcp, false),
            question,
            answer: answer.into(),
            authority: authority.into(),
            additional: additional.into(),
        }
    }
}