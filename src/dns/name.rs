use deku::prelude::*;
use deku::ctx::Endian;
use deku::bitvec::{BitSlice, BitVec, Msb0};
use std::borrow::Borrow;
use std::ops::Deref;
use std::io::Write;
use crate::dns::compression::CompressedRef;
use crate::dns::rtypes::Class;

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct DNSName(Vec<String>);

impl Deref for DNSName {
    type Target = [String];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl DNSName {
    pub(crate) fn from_url(s: &str) -> Self {
        let parts = s.split('.').filter_map(|a| {
            match a.to_string() {
                x if x.is_empty() => None,
                x => Some(x)
            }
        }).collect();
        DNSName(parts)
    }

    pub(crate) fn from_raw_string(s: &str) -> Self {
        let s = s.as_bytes();
        let mut parts = Vec::new();

        for p in s.chunks(u8::MAX as usize) {
            let p = String::from_utf8(p.to_vec()).unwrap();
            parts.push(p.to_string());
        }
        DNSName(parts)
    }
}

impl Borrow<[String]> for DNSName {
    fn borrow(&self) -> &[String] {
        self.0.as_slice()
    }
}

impl DNSName {
    fn len(&self) -> usize {
        self.0.len()
    }

    pub fn cmp(&self, other: &Self) -> NameCmp {
        let len = self.len().min(other.len());
        let mut i = 0;
        while i < len {
            if self[i] != other[i] {
                break;
            }
            i += 1;
        }
        if i == len {
            if self.len() == other.len() {
                NameCmp::Equal
            } else if self.len() < other.len() {
                NameCmp::Subdomain
            } else {
                NameCmp::Superdomain
            }
        } else {
            NameCmp::Different
        }
    }
}

impl DekuWrite<DNSNameCtxRtype> for DNSName {
    fn write(&self, output: &mut BitVec<u8, Msb0>, ctx: DNSNameCtxRtype) -> Result<(), DekuError> {
        println!("Writing DNS name {:?} {}", self.0, ctx.1);

        let mut total_msg_len = 0;

        for (index, label) in self.0.iter().enumerate() {
            let label_bytes = label.as_bytes();
            let label_len = label_bytes.len() as u8;
            total_msg_len += 1 + label_len as usize;


            if ctx.3.supports_compression() {
                if let Some(ptrindex) = ctx.2.query(self, index) {
                    let msg = Label::Pointer(ptrindex as u16);
                    msg.write(output, ())?;
                    println!("Pointer {} write at index {}", ptrindex, ctx.1);
                    return Ok(());
                }
            }
            let msg = Label::Regular(RegularMsg1 {
                length: label_len,
                content: label_bytes,
            });
            msg.write(output, ())?;
        }

        if self.0.last().map(|a| a.len() != 0).unwrap_or(true) {
            output.write(&[0]).unwrap();
        }

        if ctx.3.supports_compression() {
            ctx.2.add(self.clone(), ctx.1);
        }
        Ok(())
    }
}

impl<'a> DekuRead<'a, DNSNameCtx> for DNSName {
    fn read(input: &'a BitSlice<u8, Msb0>, ctx: DNSNameCtx) -> Result<(&'a BitSlice<u8, Msb0>, Self), DekuError> where Self: Sized {
        Self::read(input, ())
    }
}

impl<'a> DekuRead<'a, ()> for DNSName {
    fn read(mut input: &'a BitSlice<u8, Msb0>, ctx: ()) -> Result<(&'a BitSlice<u8, Msb0>, Self), DekuError> where Self: Sized {
        let mut pointer_chase_limit: i32 = 10;
        let mut decoded = Vec::new();
        loop {
            let (remaining, label) = match Label::read(input, ()) {
                Ok((remaining, label)) => (remaining, label),
                Err(err) => return Err(err),
            };

            input = remaining;

            match label {
                Label::Regular(inner) => {
                    if (inner.length == 0) {
                        break;
                    }
                    let label = String::from_utf8(inner.content.to_vec()).unwrap();
                    decoded.push(label);
                } // End of domain name
                Label::Pointer(offset) => {
                    if offset as usize >= input.len() || pointer_chase_limit == 0 {
                        return Err(DekuError::Parse("Invalid compression pointer offset".into()));
                    }

                    let (_, label_bytes) = input.split_at(offset as usize * 8);

                    input = label_bytes;
                    pointer_chase_limit -= 1;
                }
            }
        }

        return Ok((input, DNSName(decoded)));
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum NameCmp {
    Equal,
    Subdomain,
    Superdomain,
    Different,
}

#[test]
fn test_root_domain() {
    let root = DNSName::from_url(".");
    assert_eq!(root.len(), 0);

    let example = DNSName::from_url("www.example.com.");
    assert_eq!(example.len(), 3);

    let cmp = example.cmp(&root);
    assert_eq!(cmp, NameCmp::Superdomain);
}


#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "endian: Endian")]
struct RegularMsg1<'a> {
    length: u8,
    #[deku(count = "length")]
    content: &'a [u8],
}

#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
#[deku(type = "u8", bits = "2", endian = "big")]
enum Label<'a> {
    #[deku(id = "0b11")]
    Pointer(#[deku(bits = "14")] u16),
    #[deku(id_pat = "_")]
    Regular(RegularMsg1<'a>),
}

type DNSNameCtx = (Endian, usize, CompressedRef);
pub type DNSNameCtxRtype = (Endian, usize, CompressedRef, Class);
