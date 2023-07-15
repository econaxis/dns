use tokio::net::TcpListener;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::records::Records;

pub struct TcpServer {
    socket: TcpListener,
}

impl TcpServer {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let socket = TcpListener::bind("0.0.0.0:53").await?;
        Ok(Self { socket })
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        println!("TCP DNS server listening on: {:?}", self.socket.local_addr());

        let mut buf = [0u8; 1024];

        let records = Arc::new(Records::predefined());

        loop {
            let (mut stream, _) = self.socket.accept().await?;
            let size = stream.read(&mut buf).await?;
            let response = crate::servers::shared::handle_dns_packet(records.clone(), buf[..size].to_vec(), true, async move |bytes| {
                stream.write_all(&bytes).await?;
                Ok(())
            }).await;
            // Send the response back to the client
            // if let Err(err) = stream.write_all(&response).await {
            //     eprintln!("Failed to send DNS response: {:?}", err);
            // }
        }
    }
}
