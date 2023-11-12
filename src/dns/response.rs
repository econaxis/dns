use deku::prelude::*;

use crate::{
    dns::{
        compression::CompressedRef,
        header,
        header::{DNSHeader, Rcode},
        question::DNSQuestion,
        record::{DNSRecord, VecDNSRecord},
    },
    nameserver::records::{Records, ResponseSection},
};

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
    pub fn set_return_code(&mut self, error: Rcode) {
        self.header.rcode = error;
    }
    pub(crate) fn clear(&self) {
        self.compress.clear();
    }

    pub(crate) fn build_from_record_iter(id: u16, question: DNSQuestion, records: &Records, tcp: bool) -> Response {
        let mut answer = Vec::new();
        let mut authority = Vec::new();
        let mut additional = Vec::new();

        for record in records.query(&question.qname, &question.qtype) {
            match record.section {
                ResponseSection::Answer => answer.push(record.record.clone()),
                ResponseSection::Authority => authority.push(record.record.clone()),
                ResponseSection::Additional => additional.push(record.record.clone()),
            }
        }

        for record in &authority {
            if let Some(dnsname) = record.rdata.try_get_name() {
                additional.extend(records.additional_section(dnsname).map(|r| r.record.clone()));
            }
        }

        Response::new(id, question, answer, authority, additional, tcp, Rcode::NoError)
    }

    pub fn from_rcode(id: u16, question: DNSQuestion, rcode: Rcode, tcp: bool) -> Response {
        Response::new(id, question, Vec::new(), Vec::new(), Vec::new(), tcp, rcode)
    }

    pub(crate) fn new(
        id: u16,
        question: DNSQuestion,
        answer: Vec<DNSRecord>,
        authority: Vec<DNSRecord>,
        additional: Vec<DNSRecord>,
        tcp: bool,
        rcode: Rcode,
    ) -> Response {
        Response {
            compress: CompressedRef::new(tcp),
            header: header::response_header(id, answer.len(), authority.len(), additional.len(), tcp, false, rcode),
            question,
            answer: answer.into(),
            authority: authority.into(),
            additional: additional.into(),
        }
    }
}
