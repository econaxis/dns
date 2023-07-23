use std::str::FromStr;
use deku::bitvec::{BitSlice, BitVec, Msb0};
use deku::{DekuError, DekuRead, DekuWrite};
use crate::dns::name::{DNSName, DNSNameCtxRtype};
use crate::dns::rtypes::RType;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DNSText {
    inner: DNSName,
}

impl From<String> for DNSText {
    fn from(value: String) -> Self {
        DNSText {
            inner: DNSName(vec![value])
        }
    }
}



impl DekuWrite<DNSNameCtxRtype> for DNSText {
    fn write(&self, output: &mut BitVec<u8, Msb0>, mut ctx: DNSNameCtxRtype) -> Result<(), deku::DekuError> {
        // ctx.rtype = RType::TXT;
        self.inner.write(output, ctx)
    }
}

impl<'a> DekuRead<'a> for DNSText {
    fn read(input: &'a BitSlice<u8, Msb0>, ctx: ()) -> Result<(&'a BitSlice<u8, Msb0>, Self), DekuError> {
        let (input, inner) = DNSName::read(input, ctx)?;
        Ok((input, Self {
            inner
        }))
    }
}