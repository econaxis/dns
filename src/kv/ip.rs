// Automatically routes {num1}-{num2}-{num3}-{num4}.ip.henryn.ca to the IP address

use std::str::FromStr;
use crate::dns::data::RData;
use crate::dns::header::Rcode;
use crate::dns::name::DNSName;
use crate::dns::question::DNSQuestion;
use crate::dns::record::DNSRecord;
use crate::dns::response::Response;
use crate::dns::rtypes::RType;
use crate::kv::OwnedRecordItem;
use crate::nameserver::records::ResponseSection;

pub struct IPRouter {}

impl IPRouter {
    pub fn build_response(&mut self, id: u16, question: DNSQuestion, tcp: bool) -> Response {
        /// Question MUST HAVE qtype = A, qname = {num1}-{num2}-{num3}-{num4}.ip.henryn.ca
        /// id is the question ID of the query that we must propagate to the response
        println!("Got question {id} {question:?}");

        let qname = &question.qname;
        if !(qname.len() >= 3 && &qname[qname.len() - 3..] == ["ip", "henryn", "ca"]) {
            return OwnedRecordItem::empty(id, question, tcp);
        };

        if qname.len() == 3 {
            // Direct it to the base domain
            const BASE_DOMAIN_IP: [u8; 4] = [10, 0, 0, 1];
            let record = OwnedRecordItem {
                record: DNSRecord {
                    name: question.qname.clone(),
                    rtype: RType::A,
                    class: 1,
                    ttl: 0,
                    rdata: RData::Vec(BASE_DOMAIN_IP.to_vec()),
                },
                section: ResponseSection::Answer,
            };
            return OwnedRecordItem::build_response(&[record], id, question, tcp);
        }

        if qname.len() != 7 {
            let mut response = OwnedRecordItem::empty(id, question, tcp);
            response.set_return_code(Rcode::Refused);
            return response;
        }

        let ips = &question.qname[0..4];
        let ips_int: Vec<Option<u8>> = ips.iter().map(|x| u8::from_str(x).ok()).collect();

        if ips_int.iter().all(Option::is_some) {
            let ips_int: Vec<u8> = ips_int.into_iter().map(Option::unwrap).collect();
            let record = OwnedRecordItem {
                record: DNSRecord {
                    name: question.qname.clone(),
                    rtype: RType::A,
                    class: 1,
                    ttl: 0,
                    rdata: RData::Vec(ips_int),
                },
                section: ResponseSection::Answer,
            };
            OwnedRecordItem::build_response(&[record], id, question, tcp)
        } else {
            let mut response = OwnedRecordItem::empty(id, question, tcp);
            response.set_return_code(Rcode::Refused);
            return response;
        }
    }
}