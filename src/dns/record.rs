use crate::dns::{
    compression::CompressedRef,
    data::RData,
    name::DNSName,
    rtypes::{ContainsIP, RType},
};
use anyhow::{anyhow, Context};
use deku::{
    bitvec::{BitSlice, BitVec, Msb0},
    ctx::Endian,
    prelude::*,
};
use std::{net::Ipv4Addr, ops::Deref, str::FromStr};

#[derive(Debug, PartialEq, Eq, DekuRead, Clone)]
#[deku(endian = "big", ctx = "compressed: CompressedRef")]
pub struct DNSRecord {
    #[deku(ctx = "deku::byte_offset, compressed")]
    pub(crate) name: DNSName,
    pub(crate) rtype: RType,
    #[deku(bits = "16")]
    pub(crate) class: u16,
    #[deku(bits = "32")]
    pub(crate) ttl: u32,

    #[deku(
        ctx = "deku::byte_offset, compressed.clone()",
        reader = "RData::read(deku::rest, ContainsIP::from_class(*rtype))"
    )]
    pub(crate) rdata: RData,
}

impl DekuWrite<CompressedRef> for DNSRecord {
    fn write(&self, output: &mut BitVec<u8, Msb0>, ctx: CompressedRef) -> Result<(), DekuError> {
        let ctx_q = (Endian::Big, output.len(), ctx.clone(), self.rtype, true);

        let ctx_a = if self.rtype == RType::TXT {
            (Endian::Big, output.len(), ctx, self.rtype, false)
        } else {
            ctx_q.clone()
        };
        self.name.write(output, ctx_q.clone().into())?;
        self.rtype.write(output, ctx_q.0)?;
        self.class.write(output, ctx_q.0)?;
        self.ttl.write(output, ctx_q.0)?;
        self.rdata.write(output, ctx_a.into())?;
        Ok(())
    }
}

impl<'a> TryFrom<&'a str> for DNSRecord {
    // Parse records like
    // www.example.com CNAME www.example.org
    // example.com A 10.10.10.10
    type Error = anyhow::Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let mut split = value.split_whitespace();

        let name = split
            .next()
            .with_context(|| anyhow!("'name' field doesn't exist for record '{}'", value))?;
        let rtype = split
            .next()
            .with_context(|| anyhow!("'rtype' field doesn't exist for record '{}'", value))?;
        let rdata = split
            .remainder()
            .with_context(|| anyhow!("'rdata' field doesn't exist for record '{}'", value))?;

        let name = DNSName::from_url(name);
        let rtype = RType::from_str(rtype).context("Invalid record type")?;
        let rdata = parse_rdata_from_rtype(rdata, rtype)?;

        Ok(Self {
            name,
            rtype,
            class: 1,
            ttl: 60,
            rdata,
        })
    }
}

fn parse_rdata_from_rtype(rdata: &str, rtype: RType) -> anyhow::Result<RData> {
    let rdata = match rtype {
        RType::CNAME | RType::NS => RData::Name(DNSName::from_url(rdata)),
        RType::TXT => RData::Name(DNSName::from_raw_string(rdata)),
        RType::A => RData::Vec(Ipv4Addr::from_str(rdata)?.octets().to_vec()),
        _ => return Err(anyhow!("Unsupported record type")),
    };
    Ok(rdata)
}

#[derive(Debug, PartialEq)]
pub struct VecDNSRecord(Vec<DNSRecord>);

impl From<Vec<DNSRecord>> for VecDNSRecord {
    fn from(vec: Vec<DNSRecord>) -> Self {
        VecDNSRecord(vec)
    }
}

impl Deref for VecDNSRecord {
    type Target = Vec<DNSRecord>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DekuWrite<(CompressedRef, u16)> for VecDNSRecord {
    fn write(&self, output: &mut BitVec<u8, Msb0>, ctx: (CompressedRef, u16)) -> Result<(), DekuError> {
        for record in self.0.iter().take(ctx.1 as usize) {
            record.write(output, ctx.0.clone())?;
        }
        Ok(())
    }
}

impl<'a> DekuRead<'a, (CompressedRef, u16)> for VecDNSRecord {
    fn read(input: &'a BitSlice<u8, Msb0>, ctx: (CompressedRef, u16)) -> Result<(&'a BitSlice<u8, Msb0>, Self), DekuError> {
        let mut records = Vec::new();
        let mut input = input;
        for _ in 0..ctx.1 {
            let (i, record) = DNSRecord::read(input, ctx.0.clone())?;
            input = i;
            records.push(record);
        }
        Ok((input, VecDNSRecord(records)))
    }
}
