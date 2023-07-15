use deku::bitvec::{BitVec, Msb0};

pub fn bv_to_vec(mut bv: BitVec<u8, Msb0>) -> Vec<u8> {
    bv.force_align();

    assert_eq!(bv.len() % 8, 0);

    let len = bv.len() / 8;
    let mut v = bv.into_vec();
    v.truncate(len);
    v
}
