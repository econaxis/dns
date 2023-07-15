use std::str::FromStr;
use deku::ctx::Endian;
use deku::prelude::*;

pub enum ContainsIP {
    Yes,
    No,
}

impl ContainsIP {
    pub fn from_class(c: &Class) -> Self {
        match c {
            Class::A => ContainsIP::Yes,
            _ => ContainsIP::No
        }
    }
}


#[derive(Debug, PartialEq, Eq, DekuWrite, DekuRead, Clone, Copy)]
#[deku(bits = "16", type = "u16", ctx = "endian: Endian", endian = "endian")]
pub enum Class {
    CNAME = 5,
    A = 1,
    NS = 2,
    OPT = 41,
    AAAA = 28,
    TXT = 16,
}

impl Class {
    pub(crate) fn supports_compression(&self) -> bool {
        match self {
            Class::CNAME => true,
            Class::A => false,
            Class::NS => true,
            Class::OPT => false,
            Class::AAAA => false,
            Class::TXT => false,
        }
    }
}

impl FromStr for Class {
    type Err = DekuError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CNAME" => Ok(Class::CNAME),
            "A" => Ok(Class::A),
            "NS" => Ok(Class::NS),
            "OPT" => Ok(Class::OPT),
            "AAAA" => Ok(Class::AAAA),
            "TXT" => Ok(Class::TXT),
            _ => Err(DekuError::Parse("Invalid class".into()))
        }
    }
}
