use std::sync::{Arc, Mutex};
use tokio::{
    net::TcpListener,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::kv::KvStore;
use crate::nameserver::records::Records;
use crate::servers::shared::AppData;


pub struct TcpServer {
    socket: TcpListener,
}

impl TcpServer {
    pub async fn new(addr: &'static str) -> Result<Self, Box<dyn std::error::Error>> {
        let socket = TcpListener::bind(addr).await?;
        Ok(Self { socket })
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("TCP DNS server listening on: {:?}", self.socket.local_addr());

        let mut buf = [0u8; 1024];

        let records = AppData {
            records: Arc::new(Records::predefined()),
            kv: Arc::new(Mutex::new(KvStore::default())),
        };

        loop {
            let (mut stream, _) = self.socket.accept().await?;
            let size = stream.read(&mut buf).await?;
            let records = records.clone();
            tokio::spawn(async move {
                crate::servers::shared::handle_dns_packet(records, buf[..size].to_vec(), true, async move |bytes| {
                    stream.write_all(&bytes).await?;
                    Ok(())
                })
                .await
                .unwrap();
            });
        }
    }
}
