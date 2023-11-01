use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};

use crate::api::{Error, Frame, Receiver, Result, Sender};

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(100);

pub struct Tcp {
    socket: Arc<TcpStream>,
    timeout: Duration,
    key: Option<u32>,
}

impl Tcp {
    pub fn set_key(&mut self, key: u32) {
        self.key = Some(key);
    }
}

impl Sender<u32> for Tcp {
    fn send(&self, msg: &u32) -> Result<()> {
        let mask = self.key.unwrap_or_default();
        let send = mask ^ *msg;
        self.socket.as_ref().write_all(&send.to_be_bytes())?;
        self.socket.as_ref().flush()?;
        Ok(())
    }
}

impl Receiver<u32> for Tcp {
    fn recv(&self) -> Result<Option<u32>> {
        let mut buf = [0u8; 4];
        match self.socket.as_ref().read_exact(&mut buf) {
            Ok(_) => {
                let read: u32 = u32::from_be_bytes(buf);
                let mask = self.key.unwrap_or_default();
                Ok(Some(read ^ mask))
            }
            Err(e)
                if e.kind()
                    == std::io::ErrorKind::UnexpectedEof =>
            {
                Ok(None)
            }
            Err(e) => Err(Error::IO(e)),
        }
    }
}

impl From<TcpStream> for Tcp {
    fn from(socket: TcpStream) -> Self {
        Tcp {
            socket: Arc::new(socket),
            timeout: DEFAULT_TIMEOUT,
            key: None,
        }
    }
}

impl Sender<Frame> for Tcp {
    fn send(&self, msg: &Frame) -> Result<()> {
        for w in msg.words() {
            self.send(&w)?;
        }
        Ok(())
    }
}

impl Receiver<Frame> for Tcp {
    fn recv(&self) -> Result<Option<Frame>> {
        let mut words = [0u32; 8];
        for w in words.iter_mut() {
            *w = self.recv_timeout(self.timeout)?;
        }
        Ok(Some(Frame::from(words)))
    }
}
