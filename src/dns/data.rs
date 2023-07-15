use deku::{DekuError, DekuRead, DekuWrite};
use deku::bitvec::{BitSlice, BitVec, Msb0};
use deku::ctx::Endian;
use crate::dns::name::{DNSName, DNSNameCtxRtype};
use crate::dns::rtypes::ContainsIP;
use crate::utils::bv_to_vec;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum RData {
    Vec(Vec<u8>),
    Name(DNSName),
}

impl RData {
    pub fn try_get_name(&self) -> Option<&DNSName> {
        match self {
            RData::Name(name) => Some(name),
            _ => None
        }
    }
}


impl DekuWrite<DNSNameCtxRtype> for RData {
    fn write(&self, output: &mut BitVec<u8, Msb0>, ctx: DNSNameCtxRtype) -> Result<(), DekuError> {
        let mut output_data = BitVec::new();
        match self {
            RData::Vec(vec) => {
                vec.write(&mut output_data, ctx.0.clone())?;
            }
            RData::Name(name) => {
                name.write(&mut output_data, ctx.clone())?;
            }
        }

        let bytes_written = (output_data.len() / 8) as u16;
        bytes_written.write(output, ctx.0)?;

        output.append(&mut output_data);

        Ok(())
    }
}

impl DekuRead<'_, ContainsIP> for RData {
    fn read(input: &BitSlice<u8, Msb0>, ctx: ContainsIP) -> Result<(&BitSlice<u8, Msb0>, Self), DekuError> {
        let (input, bytes_written) = u16::read(input, Endian::Big)?;
        let bytes_written = bytes_written as usize;

        match ctx {
            ContainsIP::No => {
                let (input, vec) = input.split_at(bytes_written);
                let vec_u8 = bv_to_vec(vec.to_bitvec());
                Ok((input, RData::Vec(vec_u8)))
            }
            ContainsIP::Yes => {
                let (input, name) = DNSName::read(input, ())?;
                Ok((input, RData::Name(name)))
            }
        }
    }
}
