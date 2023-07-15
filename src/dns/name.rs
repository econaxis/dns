use deku::prelude::*;
use deku::ctx::Endian;
use deku::bitvec::{BitSlice, BitVec, Msb0};
use std::borrow::Borrow;
use std::cmp::Ordering;
use std::ops::Deref;
use std::io::Write;
use crate::dns::compression::CompressedRef;
use crate::dns::rtypes::RType;

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct DNSName(Vec<String>);


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
    fn len(&self) -> usize {
        self.0.len()
    }

    fn getrev(&self, idx: usize) -> &str {
        &self[self.len() - idx - 1]
    }

    pub fn cmp(&self, other: &Self) -> NameCmp {
        // Do this but in reverse order (last to first)
        let len = self.len().min(other.len());
        let mut i = 0;
        while i < len {
            if self.getrev(i) != other.getrev(i) {
                break;
            }
            i += 1;
        }
        if i == len {
            match self.len().cmp(&other.len()) {
                Ordering::Equal => NameCmp::Equal,
                Ordering::Less => NameCmp::Subdomain,
                Ordering::Greater => NameCmp::Superdomain,
            }
        } else {
            NameCmp::Different
        }
    }

}


impl Deref for DNSName {
    type Target = [String];

    fn deref(&self) -> &Self::Target {
        self.0.as_slice()
    }
}

impl Borrow<[String]> for DNSName {
    fn borrow(&self) -> &[String] {
        self.0.as_slice()
    }
}


impl DekuWrite<DNSNameCtxRtype> for DNSName {
    fn write(&self, output: &mut BitVec<u8, Msb0>, ctx: DNSNameCtxRtype) -> Result<(), DekuError> {
        for (index, label) in self.0.iter().enumerate() {
            let label_bytes = label.as_bytes();
            let label_len = label_bytes.len() as u8;


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

        if self.0.last().map_or(true, |a| !a.is_empty()) {
            output.write_all(&[0]).unwrap();
        }

        if ctx.3.supports_compression() {
            ctx.2.add(self.clone(), ctx.1);
        }
        Ok(())
    }
}

impl<'a> DekuRead<'a, DNSNameCtx> for DNSName {
    fn read(input: &'a BitSlice<u8, Msb0>, _ctx: DNSNameCtx) -> Result<(&'a BitSlice<u8, Msb0>, Self), DekuError> where Self: Sized {
        Self::read(input, ())
    }
}

impl<'a> DekuRead<'a, ()> for DNSName {
    fn read(mut input: &'a BitSlice<u8, Msb0>, _ctx: ()) -> Result<(&'a BitSlice<u8, Msb0>, Self), DekuError> where Self: Sized {
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
                    if inner.length == 0 {
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

        Ok((input, DNSName(decoded)))
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum NameCmp {
    Equal,
    Subdomain,
    Superdomain,
    Different,
}




#[derive(Debug, PartialEq, DekuRead, DekuWrite)]
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
    Regular(#[deku(endian = "")] RegularMsg1<'a>),
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use std::vec::Vec;
    use deku::bitvec::BitView;

    #[test]
    fn test_regular_msg1() {
        let input = [5, 1, 2, 3, 4, 5];
        let expected = RegularMsg1 {
            length: 5,
            content: &[1, 2, 3, 4, 5],
        };

        let (_rest, result) = RegularMsg1::from_bytes((&input, 0)).unwrap();
        assert_eq!(result, expected);

        let output = result.to_bytes().unwrap();
        assert_eq!(output, input);
    }

    #[test]
    fn test_label_pointer() {
        let input = [0b1101_0000, 0x23];
        let expected = Label::Pointer(0x1023);

        let (_rest, result) = <Label>::from_bytes((&input, 0)).unwrap();
        assert_eq!(result, expected);

        let output = result.to_bytes().unwrap();
        assert_eq!(output, input);
    }

    #[test]
    fn test_label_regular() {
        let input: Vec<u8> = vec![0b1100_1001, 0xAE, 5, 1, 2, 3, 4, 5];
        let expected_first = Label::Pointer(0x09AE);
        let expected_second = Label::Regular(RegularMsg1 {
            length: 5,
            content: &[1, 2, 3, 4, 5],
        });

        let (_rest, (first, second)) = <(Label, Label)>::read(input.view_bits(), ()).unwrap();
        assert_eq!(first, expected_first);
        assert_eq!(second, expected_second);

        let mut output = BitVec::new();
        (first, second).write(&mut output, ()).unwrap();
        assert_eq!(output, input.view_bits::<Msb0>());
    }
}

type DNSNameCtx = (Endian, usize, CompressedRef);
pub type DNSNameCtxRtype = (Endian, usize, CompressedRef, RType);


#[cfg(test)]
mod domain_tests {
    use super::*;

    fn test_urls(a: &str, b: &str) -> NameCmp {
        let name1 = DNSName::from_url(a);
        let name2 = DNSName::from_url(b);
        name1.cmp(&name2)
    }

    #[test]
    fn test_cmp_equal() {
        assert_eq!(test_urls("example.com", "example.com"), NameCmp::Equal);
    }

    #[test]
    fn test_cmp_subdomain() {
        assert_eq!(test_urls("example.com", "www.example.com"), NameCmp::Subdomain);
    }

    #[test]
    fn test_cmp_superdomain() {
        assert_eq!(test_urls("www.example.com", "example.com"), NameCmp::Superdomain);
    }

    #[test]
    fn test_cmp_multiple_subdomains() {
        assert_eq!(test_urls("www.sub.example.com", "sub.example.com"), NameCmp::Superdomain);
    }

    #[test]
    fn test_cmp_different() {
        assert_eq!(test_urls("example.com", "example.net"), NameCmp::Different);
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
}
