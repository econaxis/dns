use deku::{
    bitvec::{BitSlice, BitVec, Msb0},
    ctx::Endian,
    prelude::*,
};
use std::str::FromStr;

pub enum ContainsIP {
    Yes,
    No,
}

impl ContainsIP {
    pub fn from_class(c: RType) -> Self {
        match c {
            RType::A => ContainsIP::Yes,
            _ => ContainsIP::No,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(clippy::upper_case_acronyms)]
#[repr(u16)]
pub enum RType {
    CNAME = 5,
    A = 1,
    NS = 2,
    OPT = 41,
    AAAA = 28,
    TXT = 16,
    HTTPS = 65,
    CAA = 257,
    DS = 43,
    Unknown(u16),
}

impl DekuWrite<Endian> for RType {
    fn write(&self, output: &mut BitVec<u8, Msb0>, ctx: Endian) -> Result<(), DekuError> {
        let field = to_int(*self);
        field.write(output, ctx)
    }
}

impl DekuRead<'_, Endian> for RType {
    fn read(input: &BitSlice<u8, Msb0>, ctx: Endian) -> Result<(&BitSlice<u8, Msb0>, Self), DekuError> {
        let (rest, field) = u16::read(input, ctx)?;
        let rtype = from_int(field);
        Ok((rest, rtype))
    }
}

fn from_int(field: u16) -> RType {
    match field {
        5 => RType::CNAME,
        1 => RType::A,
        2 => RType::NS,
        41 => RType::OPT,
        28 => RType::AAAA,
        16 => RType::TXT,
        65 => RType::HTTPS,
        257 => RType::CAA,
        43 => RType::DS,
        _ => RType::Unknown(field),
    }
}

fn to_int(rtype: RType) -> u16 {
    match rtype {
        RType::CNAME => 5,
        RType::A => 1,
        RType::NS => 2,
        RType::OPT => 41,
        RType::AAAA => 28,
        RType::TXT => 16,
        RType::HTTPS => 65,
        RType::CAA => 257,
        RType::DS => 43,
        RType::Unknown(x) => x,
    }
}

impl RType {
    pub(crate) fn supports_compression(&self) -> bool {
        match self {
            RType::CNAME => true,
            RType::NS => true,
            RType::A => false,
            RType::OPT => false,
            RType::AAAA => false,
            RType::TXT => false,
            RType::HTTPS => false,
            _ => false,
        }
    }
}

impl FromStr for RType {
    type Err = DekuError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CNAME" => Ok(RType::CNAME),
            "A" => Ok(RType::A),
            "NS" => Ok(RType::NS),
            "OPT" => Ok(RType::OPT),
            "AAAA" => Ok(RType::AAAA),
            "TXT" => Ok(RType::TXT),
            _ => Err(DekuError::Parse(format!("Invalid record type: {}", s.to_string()))),
        }
    }
}
