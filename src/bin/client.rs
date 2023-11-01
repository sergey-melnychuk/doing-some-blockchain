use std::{
    env::args,
    net::{SocketAddr, TcpStream},
    time::Duration,
};

use doing_some_blockchain::{
    api::{
        Error, Frame, Receiver, Result, Sender, TAG_OK,
        TAG_PUBLIC_KEY, TAG_SECRET_SHARE,
    },
    dhke::dhke_handshake,
    tcp::Tcp,
    util::{merge, random, time},
    xor,
};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);

fn client(addr: &SocketAddr, frame: &Frame) -> Result<Frame> {
    let frame = frame.clone();
    let socket = TcpStream::connect(addr)?;
    let mut tx = Tcp::from(socket);
    let a = random();
    let key = dhke_handshake(&tx, DEFAULT_TIMEOUT, a)?;
    tx.set_key(key);
    tx.send(&frame)?;
    println!("debug: send: {frame:?}");
    let frame: Frame = tx.recv_timeout(DEFAULT_TIMEOUT)?;
    println!("debug: recv: {frame:?}");
    Ok(frame)
}

const USAGE: &str =
    "Usage: <pubkey> <host:port> <get/set> [<secret>]";

fn main() -> Result<()> {
    let args = args().skip(1).collect::<Vec<_>>();
    if args.len() < 4 {
        eprintln!("{USAGE}");
        return Err(Error::App("invalid args".to_string()));
    }

    let (((key, addr1), addr2), cmd) = args
        .get(0)
        .zip(args.get(1))
        .zip(args.get(2))
        .zip(args.get(3))
        .expect(USAGE);
    let key =
        u32::from_str_radix(key, 16).expect("invalid key hex");
    let addr1: SocketAddr =
        addr1.parse().expect("invalid peer address provided");
    let addr2: SocketAddr =
        addr2.parse().expect("invalid peer address provided");
    let peers = [addr1, addr2];

    match (cmd.as_ref(), args.get(4)) {
        ("get", _) => {
            let secret = get_secret(key, &peers)?;
            println!("{secret:0x}");
        }
        ("set", Some(secret)) => {
            let secret = u32::from_str_radix(secret, 16)
                .expect("invalid secret hex");
            set_secret(key, &peers, secret)?;
        }
        _ => {
            return Err(Error::App("invalid cmd".to_string()));
        }
    }

    Ok(())
}

fn get_secret(key: u32, peers: &[SocketAddr]) -> Result<u32> {
    println!("debug: get secret from {peers:?} [key={key:0x}]");

    let frame = Frame {
        idx: time(),
        tag: TAG_PUBLIC_KEY,
        msg: 0,
        key,
        sig: merge(key, key),
        ext: 0,
        sum: 0xFACE,
    };

    let mut secret: u32 = 0;

    let mut errors = Vec::with_capacity(peers.len());
    for addr in peers {
        let response = match client(addr, &frame) {
            Ok(frame) => frame,
            Err(e) => {
                let message =
                    format!("error: peer={addr} err={e:?}");
                errors.push(message);
                continue;
            }
        };

        if response.tag != TAG_OK {
            let message = format!(
                "error: peer={addr} tag={} ext={}",
                response.tag, response.ext
            );
            errors.push(message);
            continue;
        }
        secret ^= response.msg;
    }

    if !errors.is_empty() {
        return Err(Error::App(errors.join("; ")));
    }

    Ok(secret)
}

fn set_secret(
    key: u32,
    peers: &[SocketAddr],
    secret: u32,
) -> Result<()> {
    println!(
        "debug: set secret '{secret}' to {peers:?} [key={key:0x}]"
    );

    let shares = xor::split(secret, peers.len(), random);
    assert_eq!(xor::merge(&shares), secret); // better safe than sorry!

    let mut errors = Vec::with_capacity(peers.len());
    for (addr, msg) in peers.iter().zip(shares.iter()) {
        let frame = Frame {
            idx: time(),
            tag: TAG_SECRET_SHARE,
            msg: *msg,
            key,
            sig: merge(key, key),
            ext: 0,
            sum: 0xFACE,
        };
        let response = client(addr, &frame)?;

        if response.tag != TAG_OK {
            let message = format!(
                "error: peer={addr} tag={} ext={}",
                response.tag, response.ext
            );
            errors.push(message);
            continue;
        }
    }

    if !errors.is_empty() {
        return Err(Error::App(errors.join("; ")));
    }

    Ok(())
}
