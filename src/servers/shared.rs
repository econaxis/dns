use deku::bitvec::{BitSlice, BitVec, Msb0};
use deku::{DekuRead, DekuWrite};
use std::future::Future;
use std::sync::Arc;
use tokio::task::spawn_blocking;
use crate::dns::question::Question;
use crate::dns::response::Response;
use crate::nameserver::records::Records;
use crate::utils::bv_to_vec;

fn waste_thread() {
    let mut string = String::new();
    for a in 0..10000 {
        string.push_str(format!("123 4 5 {}", a * 10).as_str());
    }
}

fn handle_dns_packet1(records: &Records, data: &[u8], tcp: bool) -> Vec<u8> {
    // Parse the DNS question from the packet
    let bitslice = BitSlice::from_slice(data);

    for byte in data {
        print!("{:2x} ", byte);
    }
    print!("\n");
    let dns_question = match Question::read(bitslice, tcp) {
        Ok((_, dns_question)) => dns_question,
        Err(err) => {
            eprintln!("Failed to parse DNS question: {:?}", err);
            return vec![];
        }
    };

    println!("{:?}", dns_question);

    let mut response = Response::build_from_record_iter(dns_question.header.id, dns_question.question.clone(), records, tcp);

    let mut bitvec = BitVec::new();
    response.write(&mut bitvec, tcp).unwrap();


    let total_len = (bitvec.as_raw_slice().len() - response.header.message_len_offset()) as u16;
    let updated = response.header.update_from_total_msg_len(total_len);

    if updated && response.header.tc > 0 {
        response.clear();
        bitvec = BitVec::new();

        // Set all lengths of responses to 0 except question
        response.header.ancount = 0;
        response.header.nscount = 0;
        response.header.arcount = 0;

        response.write(&mut bitvec, tcp).unwrap();
    } else if updated {
        let mut header_bv = BitVec::new();

        response.header.write(&mut header_bv, tcp).unwrap();
        if response.header.tc > 0 {
            bitvec = header_bv;
        } else {
            bitvec.splice(0..header_bv.len(), header_bv);
        }
    }

    waste_thread();


    let response = bv_to_vec(bitvec);
    return response;
}

pub async fn handle_dns_packet<F: FnOnce(Vec<u8>) -> T + 'static, T: Future<Output=std::io::Result<()>> + 'static>(records: Arc<Records>, data: Vec<u8>, tcp: bool, send_callback: F) -> std::io::Result<()> {
    let res = spawn_blocking(move || {
        handle_dns_packet1(&records, &data, tcp)
    }).await.unwrap();
    send_callback(res).await
}
