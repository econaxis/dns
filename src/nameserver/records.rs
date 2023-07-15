use crate::dns::record::DNSRecord;
use crate::dns::name::{DNSName, NameCmp};
use crate::dns::rtypes::RType;
use crate::nameserver::default_records::DEFAULT_RECORDS;

#[derive(Default, Debug, Clone)]
pub struct Records {
    inner: Vec<DNSRecord>,
}

pub enum ResponseSection {
    Answer,
    Authority,
    Additional,
}

pub struct RecordItem<'a> {
    pub record: &'a DNSRecord,
    pub section: ResponseSection,
}

impl FromIterator<DNSRecord> for Records {
    fn from_iter<T: IntoIterator<Item=DNSRecord>>(iter: T) -> Self {
        Records { inner: iter.into_iter().collect() }
    }
}

impl Records {
    pub fn predefined() -> Self {
        Self::from_iter(DEFAULT_RECORDS.into_iter().cloned().map(DNSRecord::try_from).map(Result::unwrap))
    }
    fn map_matching<'a>(&'a self, name: &'a DNSName) -> impl Iterator<Item = (&'a DNSRecord, NameCmp)> {
        self.inner.iter().filter_map(move |p| match p.name.cmp(name) {
            x @ NameCmp::Equal | x@ NameCmp::Subdomain | x@NameCmp::Superdomain=> Some((p, x)),
            _ => None,
        })
    }

    pub fn query<'a: 'b, 'b>(&'a self, name: &'a DNSName, qtype: &'b RType) -> impl Iterator<Item=RecordItem<'a>> + 'b {
        self.map_matching(name).filter_map(move |(record, cmp)|{
            match cmp {
                NameCmp::Equal | NameCmp::Subdomain | NameCmp::Superdomain if record.rtype == RType::NS => Some(RecordItem {
                    record, section: ResponseSection::Authority
                }),
                // We have record = NS example.com and name = www3.example.com
                // cmp returns subdomain
                NameCmp::Equal => {
                    if qtype == &record.rtype {
                        Some(RecordItem {
                            record, section: ResponseSection::Answer
                        })
                    } else {
                        // Put everything else in Additional just for fun
                        Some(RecordItem {
                            record, section: ResponseSection::Additional
                        })
                    }
                },
                _ => None,
            }
        })
    }

    pub fn additional_section<'a>(&'a self, addl_name: &'a DNSName) -> impl Iterator<Item=RecordItem<'a>> {
        // Do it if there was an NS record in the authority section
        self.map_matching(addl_name).filter_map(|(record, cmp)|{
            match cmp {
                NameCmp::Equal | NameCmp::Subdomain if record.rtype == RType::A => Some(RecordItem {
                    record, section: ResponseSection::Additional
                }),
                _ => None,
            }
        })
    }
}