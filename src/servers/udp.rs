use crate::nameserver::records::Records;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use crate::kv::KvStore;
use crate::servers::shared::AppData;

pub struct UdpServer {
    socket: Arc<UdpSocket>,
}

impl UdpServer {
    pub async fn new(addr: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        Ok(Self { socket })
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("UDP DNS server listening on: {:?}", self.socket.local_addr());

        let mut buf = [0u8; 1024];

        let records = AppData {
            records: Arc::new(Records::predefined()),
            kv: Arc::new(Mutex::new(KvStore::default())),
        };

        loop {
            let (size, addr) = self.socket.recv_from(&mut buf).await?;
            let socket = self.socket.clone();
            let records = records.clone();
            tokio::spawn(async move {
                crate::servers::shared::handle_dns_packet(records, buf[..size].to_vec(), false, async move |bytes| {
                    socket.send_to(&bytes, addr).await?;
                    Ok(())
                })
                .await
                .unwrap();
            });
        }
    }
}
