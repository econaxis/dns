mod ip;
mod ip1;
pub use ip::IPRouter;

/// DNS KV store
/// Usage:
///
/// dig {key}.{value} @localhost to insert a key/value pair
/// For example, dig foo.bar @localhost
///
/// dig {key} @localhost to retrieve a value
/// For example, dig foo @localhost will return a TXT record with "bar" as the content
///
/// This doesn't support "." in any key or value pair.
/// TODO: how to support binary strings as values?
/// Encode as base64


use std::collections::HashMap;
use crate::dns::data::RData;
use crate::dns::header::Rcode;
use crate::dns::name::DNSName;
use crate::dns::question::DNSQuestion;
use crate::dns::record::DNSRecord;
use crate::dns::response::Response;
use crate::dns::rtypes::RType;
use crate::dns::text::DNSText;
use crate::nameserver::records::{ResponseSection};

// TODO: change storage to be persistent
type Storage = HashMap<String, String>;

#[derive(Default, Debug)]
pub struct KvStore {
    inner: Storage,
}


#[derive(Debug)]
pub struct OwnedRecordItem {
    pub record: DNSRecord,
    pub section: ResponseSection,
}

impl OwnedRecordItem {
    pub fn empty(id: u16, question: DNSQuestion, tcp: bool) -> Response {
        Self::build_response(&[], id, question, tcp)
    }
    pub fn build_response(list: &[Self], id: u16, question: DNSQuestion, tcp: bool) -> Response {
        let mut answer = Vec::new();
        let mut authority = Vec::new();
        let mut additional = Vec::new();

        for record in list {
            match record.section {
                ResponseSection::Answer => answer.push(record.record.clone()),
                ResponseSection::Authority => authority.push(record.record.clone()),
                ResponseSection::Additional => additional.push(record.record.clone()),
            }
        }

        let rcode = if list.is_empty() {
            Rcode::NxDomain
        } else {
            Rcode::NoError
        };

        Response::new(id, question, answer, authority, additional, tcp, rcode)
    }
}

impl KvStore {
    pub fn query_put<'a>(&'a mut self, key: &str, value: &str, qtype: &'a RType) -> Vec<OwnedRecordItem> {
        let mut answer = Vec::new();

        match qtype {
            RType::A | RType::TXT => {
                // Get the actual value
                self.inner.insert(key.to_string(), value.to_string());
                answer.extend(self.query_get(key, &RType::TXT));
            }
            _ => {}
        };

        answer

    }

    pub fn query_get<'a>(&'a self, name_str: &str, qtype: &'a RType) -> Vec<OwnedRecordItem> {
        let mut answer = Vec::new();

        match qtype {
            RType::TXT | RType::A => {
                // Get the actual value
                self.inner.get(name_str).map(|x| OwnedRecordItem {
                    record: DNSRecord {
                        name: DNSName(vec![name_str.to_string()]),
                        rtype: RType::TXT,
                        class: 1,
                        ttl: 0,
                        rdata: RData::Text(DNSText::from(x.clone())),
                    },
                    section: ResponseSection::Answer,
                }).map(|x| answer.push(x));
            }
            _ => {
                // By sending an empty `answer`, automatically sends NXDOMAIN
            }
        };
        println!("Query get: {:?}", &answer);

        answer
    }

    fn build_response_internal(&mut self, id: u16, question: DNSQuestion, tcp: bool) -> anyhow::Result<Response> {
        let answer = match question.qname.len() {
            1 => {
                // Read record (dig {key} @localhost)
                if question.qname.len() != 1 {
                    return Err(anyhow::anyhow!("Invalid query: {:?}", question.qname));
                }

                let name_str = question.qname[0].to_string();
                println!("name_str: {:?}", name_str);
                self.query_get(&name_str, &question.qtype)
            }

            2 => {
                // Write record
                // dig {key}.{value} @localhost
                if question.qname.len() != 2 {
                    return Err(anyhow::anyhow!("Invalid query: {:?}", question.qname));
                }

                let name_str = question.qname[0].to_string();
                let value_str = question.qname[1].to_string();
                println!("name_str: {:?}, value_str: {:?}", name_str, value_str);
                self.query_put(&name_str, &value_str, &question.qtype)
            }
            _ => {
                return Err(anyhow::anyhow!("Invalid query: {:?}", question.qname));
            }
        };

        Ok(OwnedRecordItem::build_response(&answer, id, question, tcp))
    }

    pub fn build_response(&mut self, id: u16, question: DNSQuestion, tcp: bool) -> Response {
        self.build_response_internal(id, question.clone(), tcp).unwrap_or_else(|err| {
            eprintln!("Error building response: {:?}", err);
            Response::new(id, question,  vec![], vec![], vec![], tcp, Rcode::ServerFailure)
        })
    }

}
