use std::sync::{Arc, RwLock};
use std::ops::Deref;
use std::collections::HashMap;
use crate::dns::name::DNSName;

#[derive(Debug, PartialEq, Clone)]
pub struct CompressedRef(Arc<Compressed>);

impl CompressedRef {
    pub(crate) fn new(is_tcp: bool) -> Self {
        CompressedRef(Arc::new(Compressed {
            pointers: RwLock::new(HashMap::new()),
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
    pub(crate) pointers: RwLock<HashMap<DNSName, usize>>,
    is_tcp: bool,
}

impl PartialEq for Compressed {
    fn eq(&self, other: &Self) -> bool {
        return false;
    }
}


impl Compressed {
    pub(crate) fn add(&self, name: DNSName, mut offset: usize) {
        if self.is_tcp {
            offset -= 2;
        }
        let offset = 0xC000 | offset;
        let mut pointers = self.pointers.write().unwrap();
        pointers.insert(name, offset);
    }

    pub(crate) fn query(&self, name: &DNSName, offset: usize) -> Option<usize> {
        let name1 = &name[offset..];
        let pointers = self.pointers.read().unwrap();
        pointers.get(name1).map(|x| *x)
    }
}
