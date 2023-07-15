#![feature(slice_pattern)]
#![feature(async_closure)]
#![feature(str_split_whitespace_remainder)]

use tokio::task::spawn_blocking;

use tokio::join;

mod records;
mod default_records;

extern crate core;

mod dns;
mod utils;
mod servers;

use tokio::net::{TcpListener, UdpSocket};
use servers::tcp::TcpServer;
use servers::udp::UdpServer;


#[tokio::main]
async fn main() {
    let server = UdpServer::new().await.unwrap();
    let server1 = TcpServer::new().await.unwrap();

    let res = tokio::try_join!(server.run(), server1.run());


    println!("Server crashed: {:?}", res);
}



