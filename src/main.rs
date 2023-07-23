#![feature(slice_pattern)]
#![feature(async_closure)]
#![feature(str_split_whitespace_remainder)]

mod nameserver;

mod dns;
mod servers;
mod utils;
mod kv;

use servers::{tcp::TcpServer, udp::UdpServer};
use std::error::Error;

async fn server() -> Result<(), Box<dyn Error>> {
    const DNSADDR: &str = "0.0.0.0:53";

    let server = UdpServer::new(DNSADDR).await?;
    let server1 = TcpServer::new(DNSADDR).await?;

    let res = tokio::try_join!(server.run(), server1.run());

    println!("Server crashed: {:?}", res);

    Ok(())
}

#[tokio::main]
async fn main() {
    server().await.unwrap();
}
