use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::api::{Error, Receiver, Result, Sender};

type Network = Arc<Mutex<HashMap<String, Vec<u32>>>>;

pub fn network() -> Network {
    Arc::new(Mutex::new(HashMap::with_capacity(32)))
}

pub struct Probe {
    src: String,
    dst: String,
    net: Network,
}

impl Sender<u32> for Probe {
    fn send(&self, msg: &u32) -> Result<()> {
        let mut guard = self
            .net
            .lock()
            .map_err(|e| Error::Other(format!("{e}")))?;
        guard.entry(self.dst.clone()).or_default().push(*msg);
        Ok(())
    }
}

impl Receiver<u32> for Probe {
    fn recv(&self) -> Result<Option<u32>> {
        let mut guard = self
            .net
            .lock()
            .map_err(|e| Error::Other(format!("{e}")))?;
        let msg = guard
            .get_mut(&self.src)
            .and_then(|queue| queue.pop());
        Ok(msg)
    }
}

impl Probe {
    pub fn open(
        addr: &(String, String, Network),
    ) -> Result<Self> {
        let (src, dst, net) = addr;
        Ok(Self {
            src: src.to_owned(),
            dst: dst.to_owned(),
            net: net.clone(),
        })
    }
}
