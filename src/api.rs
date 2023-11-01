use std::{thread, time::Duration};

#[derive(Debug)]
pub enum Error {
    IO(std::io::Error),
    App(String),
    Other(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

impl From<Box<dyn std::any::Any + Send + 'static>> for Error {
    fn from(e: Box<dyn std::any::Any + Send + 'static>) -> Self {
        Self::Other(format!("{e:?}"))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait Sender<T: 'static>: Sized {
    fn send(&self, msg: &T) -> Result<()>;
}

pub trait Receiver<T: 'static>: Sized {
    fn recv(&self) -> Result<Option<T>>;

    fn recv_timeout(&self, timeout: Duration) -> Result<T> {
        if let Some(received) = self.recv()? {
            return Ok(received);
        }
        thread::sleep(timeout / 2);
        if let Some(received) = self.recv()? {
            return Ok(received);
        }
        thread::sleep(timeout / 2);
        match self.recv()? {
            Some(received) => Ok(received),
            None => {
                let kind = std::io::ErrorKind::TimedOut;
                let e = std::io::Error::new(kind, "timeout");
                Err(Error::IO(e))
            }
        }
    }
}

pub const TAG_SECRET_SHARE: u32 = 1;
pub const TAG_PUBLIC_KEY: u32 = 2;
pub const TAG_REFRESH: u32 = 3;

pub const TAG_HELLO: u32 = 255;

pub const TAG_OK: u32 = 200;
pub const TAG_BAD_REQUEST: u32 = 400;
pub const TAG_SERVER_ERROR: u32 = 500;

pub const ERR_NOT_FOUND: u32 = 32001;
pub const ERR_EXPIRED: u32 = 32002;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub idx: u32,
    pub tag: u32,
    pub msg: u32,
    pub key: u32,
    pub sig: u64, // signature over `idx || tag || msg`
    pub ext: u32,
    pub sum: u32, // crc32
}

impl Frame {
    pub fn words(&self) -> [u32; 8] {
        let mut ret = [0u32; 8];
        ret[0] = self.idx;
        ret[1] = self.tag;
        ret[2] = self.msg;
        ret[3] = self.key;
        let (hi, lo) = crate::util::split(self.sig);
        ret[4] = hi;
        ret[5] = lo;
        ret[6] = self.ext;
        ret[7] = self.sum;
        ret
    }

    pub fn from(words: [u32; 8]) -> Self {
        Self {
            idx: words[0],
            tag: words[1],
            msg: words[2],
            key: words[3],
            sig: crate::util::merge(words[4], words[5]),
            ext: words[6],
            sum: words[7],
        }
    }
}
