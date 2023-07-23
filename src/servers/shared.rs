use crate::{
    dns::{header::Rcode, question::Question, response::Response, rtypes::RType},
    nameserver::records::Records,
    utils::bv_to_vec,
};
use deku::{
    bitvec::{BitSlice, BitVec}, DekuRead, DekuWrite,
};
use std::{future::Future, sync::Arc};
use std::sync::Mutex;
use tokio::task::spawn_blocking;
use crate::kv::KvStore;


#[derive(Clone)]
pub struct AppData {
    pub records: Arc<Records>,
    pub kv: Arc<Mutex<KvStore>>
}
fn handle_dns_packet1(ad: AppData, data: &[u8], tcp: bool) -> Vec<u8> {
    let _records = ad.records;
    let kv = ad.kv;
    // Parse the DNS question from the packet
    let bitslice = BitSlice::from_slice(data);

    let dns_question = match Question::read(bitslice, tcp) {
        Ok((_, dns_question)) => dns_question,
        Err(err) => {
            eprintln!("Failed to parse DNS question: {err:?}");
            return vec![];
        }
    };

    if matches!(dns_question.question.qtype, RType::Unknown(_)) {
        eprintln!("Unknown qtype: {:?}", dns_question.question.qtype);
        let response = Response::from_rcode(dns_question.header.id, dns_question.question, Rcode::NotImplemented, tcp);
        let mut bitvec = BitVec::new();
        response.write(&mut bitvec, tcp).unwrap();
        return bv_to_vec(bitvec);
    }

    println!("{dns_question:?}");

    // let mut response = Response::build_from_record_iter(dns_question.header.id, dns_question.question, &records, tcp);

    let mut response = kv.lock().unwrap().build_response(dns_question.header.id, dns_question.question, tcp);
    let mut bitvec = BitVec::new();
    response.write(&mut bitvec, tcp).unwrap();

    let total_len = (bitvec.as_raw_slice().len() - response.header.message_len_offset()).try_into().unwrap();
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

    bv_to_vec(bitvec)
}

pub async fn handle_dns_packet<F: FnOnce(Vec<u8>) -> T, T: Future<Output = std::io::Result<()>>>(
    records: AppData,
    data: Vec<u8>,
    tcp: bool,
    send_callback: F,
) -> std::io::Result<()> {
    let res = spawn_blocking(move || handle_dns_packet1(records, &data, tcp)).await.unwrap();
    send_callback(res).await
}
