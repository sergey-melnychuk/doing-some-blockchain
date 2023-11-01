use std::{
    collections::HashMap,
    env::args,
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
    time::Duration,
};

use doing_some_blockchain::{
    api::{
        Frame, Receiver, Result, Sender, ERR_NOT_FOUND,
        TAG_BAD_REQUEST, TAG_OK, TAG_PUBLIC_KEY, TAG_REFRESH,
        TAG_SECRET_SHARE,
    },
    dhke::dhke_handshake,
    tcp::Tcp,
    util::{merge, random, time},
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

trait Transport<K>:
    Sender<u32> + Receiver<u32> + Sender<Frame> + Receiver<Frame>
{
    fn set_session_key(&mut self, key: K);
}

impl Transport<u32> for Tcp {
    fn set_session_key(&mut self, key: u32) {
        self.set_key(key);
    }
}

trait Storage<K, S, M>: Send {
    fn set(&mut self, key: K, secret: S);
    fn get(&mut self, key: K) -> Option<S>;
    fn patch(&mut self, key: K, mask: M);
}

struct DB {
    data: HashMap<u32, Vec<u32>>,
    hits: HashMap<u32, usize>,
}

impl DB {
    fn new() -> Self {
        Self {
            data: HashMap::new(),
            hits: HashMap::new(),
        }
    }
}

impl Storage<u32, u32, u32> for DB {
    fn set(&mut self, key: u32, secret: u32) {
        self.data.insert(key, vec![secret]);
        self.hits.insert(key, 0);
    }

    fn get(&mut self, key: u32) -> Option<u32> {
        let idx = self.hits.get(&key).cloned()?;
        *self.hits.get_mut(&key).unwrap() += 1;
        self.data.get(&key).and_then(|vec| vec.get(idx)).cloned()
    }

    fn patch(&mut self, key: u32, mask: u32) {
        if let Some(next) = self
            .data
            .get(&key)
            .and_then(|vec| vec.last().cloned())
            .map(|last| last ^ mask)
        {
            self.data.entry(key).or_default().push(next);
        }
    }
}

fn handle<T: Transport<u32>, S: Storage<u32, u32, u32>>(
    tx: &mut T,
    key: u32,
    db: Arc<Mutex<S>>,
    peer: SocketAddr,
    sync: bool,
) -> Result<()> {
    {
        let a = random();
        let key = dhke_handshake(tx, DEFAULT_TIMEOUT, a)?;
        tx.set_session_key(key);
    }

    let frame: Frame = tx.recv_timeout(DEFAULT_TIMEOUT)?;
    println!("debug: recv: {frame:?}");

    let mut trigger_refresh = false;
    let response = match frame.tag {
        TAG_SECRET_SHARE => {
            // skipping: validate checksum & signature
            {
                let mut db = db.lock().unwrap();
                db.set(frame.key, frame.msg);
            }
            Frame {
                idx: time(),
                tag: TAG_OK,
                msg: 200,
                key,
                sig: merge(key, key),
                ext: 0,
                sum: 42,
            }
        }
        TAG_PUBLIC_KEY => {
            // skipping: validate checksum & signature
            if let Some(msg) = {
                let mut db = db.lock().unwrap();
                db.get(frame.key)
            } {
                trigger_refresh = sync;
                Frame {
                    idx: time(),
                    tag: TAG_OK,
                    msg,
                    key,
                    sig: merge(key, key),
                    ext: 0,
                    sum: 42,
                }
            } else {
                Frame {
                    idx: time(),
                    tag: TAG_BAD_REQUEST,
                    msg: 0,
                    key,
                    sig: merge(key, key),
                    ext: ERR_NOT_FOUND,
                    sum: 42,
                }
            }
        }
        TAG_REFRESH => {
            {
                let mut db = db.lock().unwrap();
                db.patch(frame.ext, frame.msg);
                println!(
                    "debug: patch: key={:0x} mask={:0x}",
                    frame.ext, frame.msg
                );
            }
            Frame {
                idx: time(),
                tag: TAG_OK,
                msg: 0,
                key,
                sig: merge(key, key),
                ext: 0,
                sum: 0,
            }
        }
        tag => Frame {
            idx: time(),
            tag: TAG_BAD_REQUEST,
            msg: 0,
            key,
            sig: merge(key, key),
            ext: tag,
            sum: 42,
        },
    };

    println!("debug: send: {response:?}");
    tx.send(&response)?;

    if trigger_refresh {
        refresh(key, db.clone(), peer, frame.key)?;
    }

    Ok(())
}

fn server(
    addr: SocketAddr,
    key: u32,
    peer: SocketAddr,
    db: Arc<Mutex<DB>>,
    sync: bool,
) -> JoinHandle<Result<()>> {
    let h = thread::spawn(move || {
        let listener = TcpListener::bind(addr)?;
        while let Ok((socket, _remote)) = listener.accept() {
            let db = db.clone();
            thread::spawn(move || {
                // Thread-per-request: gross simplification
                // but "enough for the demo LOL" (c)
                let mut tx = Tcp::from(socket);
                handle(&mut tx, key, db, peer, sync)
            });
        }
        Ok(())
    });
    thread::sleep(Duration::from_millis(100));
    h
}

fn refresh<S: Storage<u32, u32, u32>>(
    key: u32,
    db: Arc<Mutex<S>>,
    peer: SocketAddr,
    owner: u32,
) -> Result<()> {
    let mask = random();
    let refresh = Frame {
        idx: time(),
        tag: TAG_REFRESH,
        msg: mask,
        key,
        sig: merge(key, key),
        ext: owner,
        sum: 42,
    };

    let mut tx = Tcp::from(TcpStream::connect(peer)?);
    {
        let a = random();
        let key = dhke_handshake(&tx, DEFAULT_TIMEOUT, a)?;
        tx.set_key(key);
    }

    tx.send(&refresh)?;
    println!("debug: send: {refresh:?}");
    let refresh: Frame = tx.recv_timeout(DEFAULT_TIMEOUT)?;
    println!("debug: recv: {refresh:?}");
    if refresh.tag == TAG_OK {
        let mut db = db.lock().unwrap();
        db.patch(owner, mask);
        println!(
            "debug: patch: key={:0x} mask={:0x}",
            owner, mask
        );
    }
    Ok(())
}

const USAGE: &str = "Usage: <key> <port> <peer> [sync]";

fn main() {
    let args = args().skip(1).collect::<Vec<_>>();

    let ((key, port), peer) = args
        .get(0)
        .zip(args.get(1))
        .zip(args.get(2))
        .expect(USAGE);
    let key =
        u32::from_str_radix(key, 16).expect("invalid key hex");
    let port: u16 = port.parse().expect("invalid port provided");
    let peer: SocketAddr =
        peer.parse().expect("invalid peer address provided");

    let sync =
        args.get(3).map(|arg| arg == "sync").unwrap_or_default();

    println!("debug: key={key:0x} port={port}, peer={peer:?} sync={sync}");
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let db = Arc::new(Mutex::new(DB::new()));
    let jh = server(addr, key, peer, db, sync);
    let _ = jh.join().expect("server process failed");
}

#[cfg(test)]
mod tests {
    use std::net::TcpStream;

    use super::*;

    fn client(addr: SocketAddr, frame: &Frame) -> Result<Frame> {
        let frame = frame.clone();
        let socket = TcpStream::connect(addr)?;
        let mut tx = Tcp::from(socket);
        let a = random();
        let key = dhke_handshake(&tx, DEFAULT_TIMEOUT, a)?;
        tx.set_key(key);
        tx.send(&frame)?;
        let frame: Frame = tx.recv_timeout(DEFAULT_TIMEOUT)?;
        Ok(frame)
    }

    fn server(addr: SocketAddr) -> JoinHandle<Result<()>> {
        let h = thread::spawn(move || {
            let listener = TcpListener::bind(addr)?;
            if let Ok((socket, _remote)) = listener.accept() {
                let mut tx = Tcp::from(socket);
                {
                    let a = random();
                    let key =
                        dhke_handshake(&tx, DEFAULT_TIMEOUT, a)?;
                    tx.set_session_key(key);
                }

                let frame: Frame =
                    tx.recv_timeout(DEFAULT_TIMEOUT)?;
                tx.send(&frame)?;
            }
            Ok(())
        });
        thread::sleep(Duration::from_millis(100));
        h
    }

    #[test]
    fn test_echo() -> Result<()> {
        let port: u16 = 32456;
        let addr: SocketAddr = ([127, 0, 0, 1], port).into();
        let server = server(addr);

        let frame: Frame = Frame {
            idx: 0x01020304,
            tag: 0x05060708,
            msg: 0x090A0B0C,
            key: 0xCAFEBABE,
            sig: 0x0102030405060708,
            ext: 0x090A0B0C,
            sum: 0x0D0E0F00,
        };
        let rcvd = client(addr, &frame)?;
        server.join()??;

        assert_eq!(rcvd, frame);
        Ok(())
    }
}
