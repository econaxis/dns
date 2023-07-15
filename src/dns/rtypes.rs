use std::str::FromStr;
use deku::ctx::Endian;
use deku::prelude::*;

pub enum ContainsIP {
    Yes,
    No,
}

impl ContainsIP {
    pub fn from_class(c: &RType) -> Self {
        match c {
            RType::A => ContainsIP::Yes,
            _ => ContainsIP::No
        }
    }
}


#[derive(Debug, PartialEq, Eq, DekuWrite, DekuRead, Clone, Copy)]
#[deku(bits = "16", type = "u16", ctx = "endian: Endian", endian = "endian")]
pub enum RType {
    CNAME = 5,
    A = 1,
    NS = 2,
    OPT = 41,
    AAAA = 28,
    TXT = 16,
}

impl RType {
    pub(crate) fn supports_compression(&self) -> bool {
        match self {
            RType::CNAME => true,
            RType::A => false,
            RType::NS => true,
            RType::OPT => false,
            RType::AAAA => false,
            RType::TXT => false,
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
            _ => Err(DekuError::Parse(format!("Invalid record type: {}", s.to_string())))
        }
    }
}
