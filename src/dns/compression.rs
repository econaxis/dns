use crate::dns::name::DNSName;
use std::{cell::RefCell, collections::HashMap, ops::Deref, rc::Rc};

const ENABLED: bool = false;

#[derive(Debug, PartialEq, Clone)]
pub struct CompressedRef(Rc<Compressed>);

impl CompressedRef {
    pub(crate) fn new(is_tcp: bool) -> Self {
        CompressedRef(Rc::new(Compressed {
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
    fn eq(&self, _other: &Self) -> bool {
        false
    }
}

impl Compressed {
    pub fn clear(&self) {
        let mut pointers = self.pointers.borrow_mut();
        pointers.clear();
    }

    pub(crate) fn add(&self, name: DNSName, mut offset: usize) {
        if !ENABLED {
            return;
        }
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
        pointers.get(name1).copied()
    }
}
