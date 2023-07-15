use std::sync::Arc;
use tokio::net::UdpSocket;
use crate::records::Records;

pub struct UdpServer {
    socket: Arc<UdpSocket>,
}

impl UdpServer {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:53").await?);
        Ok(Self { socket })
    }
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("UDP DNS server listening on: {:?}", self.socket.local_addr());

        let mut buf = [0u8; 1024];

        let records = Arc::new(Records::predefined());

        loop {
            let (mut size, addr) = self.socket.recv_from(&mut buf).await?;
            let socket = self.socket.clone();
            let response = crate::servers::shared::handle_dns_packet(records.clone(), buf[..size].to_vec(), false, async move |bytes| {
                socket.send_to(&bytes, addr).await?;
                Ok(())
            }).await;
        }
    }
}
