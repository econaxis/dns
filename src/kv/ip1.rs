use std::collections::HashMap;
use crate::dns::question::DNSQuestion;

type IpAddr = [u8; 4];

pub struct Classic {
    domains: HashMap<String, IpAddr>
}

impl Classic {
    fn handle_write(&mut self, domain: String, ip: IpAddr) {
        self.domains.insert(domain, ip);
    }

    fn handle_query(&mut self, question: DNSQuestion) {
        let qname = &question.qname;

    }
}