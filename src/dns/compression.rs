use std::cell::{Ref, RefCell};
use std::sync::{Arc, RwLock};
use std::ops::Deref;
use std::collections::HashMap;
use crate::dns::name::DNSName;

#[derive(Debug, PartialEq, Clone)]
pub struct CompressedRef(Arc<Compressed>);

impl CompressedRef {
    pub(crate) fn new(is_tcp: bool) -> Self {
        CompressedRef(Arc::new(Compressed {
            pointers: RefCell::new(HashMap::new()),
            is_tcp,
        }))
    }
}

impl Deref for CompressedRef {
    type Target = Compressed;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}


#[derive(Debug)]
pub struct Compressed {
    pub(crate) pointers: RefCell<HashMap<DNSName, usize>>,
    is_tcp: bool,
}

impl PartialEq for Compressed {
    fn eq(&self, other: &Self) -> bool {
        return false;
    }
}


impl Compressed {
    pub fn clear(&self) {
        let mut pointers = self.pointers.borrow_mut();
        pointers.clear();
    }
    pub(crate) fn add(&self, name: DNSName, mut offset: usize) {
        if self.is_tcp {
            offset -= 2;
        }
        let offset = 0xC000 | offset;
        let mut pointers = self.pointers.borrow_mut();
        pointers.insert(name, offset);
    }

    pub(crate) fn query(&self, name: &DNSName, offset: usize) -> Option<usize> {
        let name1 = &name[offset..];
        let pointers = self.pointers.borrow();
        pointers.get(name1).map(|x| *x)
    }
}
