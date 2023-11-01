use std::time::Duration;

use crate::api::{Receiver, Result, Sender};

pub type Int = u64;

pub const BASE: Int = 7;

// See https://en.wikipedia.org/wiki/Mersenne_prime
pub const MODULUS: Int = 2147483647;

// https://en.wikipedia.org/wiki/Modular_exponentiation#Right-to-left_binary_method
pub fn modular_pow(
    mut base: Int,
    mut exponent: Int,
    modulus: Int,
) -> Int {
    if modulus == 1 {
        return 0;
    }
    let mut result = 1;
    base %= modulus;
    while exponent > 0 {
        if exponent % 2 == 1 {
            result =
                (result % modulus * base % modulus) % modulus;
        }
        exponent >>= 1;
        base = (base % modulus * base % modulus) % modulus;
    }
    result
}

pub fn dhke_handshake<T: Sender<u32> + Receiver<u32>>(
    transport: &T,
    timeout: Duration,
    a: u32,
) -> Result<u32> {
    let pow = modular_pow(BASE, a as Int, MODULUS);
    transport.send(&(pow as u32))?;
    let b = transport.recv_timeout(timeout)?;
    let secret = modular_pow(b as Int, a as Int, MODULUS);
    Ok(secret as u32)
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::*;
    use crate::testkit::*;

    #[test]
    fn test_dfke_handshake() {
        let network = network();

        let one = "1".to_string();
        let two = "2".to_string();
        let t1 = Probe::open(&(
            one.clone(),
            two.clone(),
            network.clone(),
        ))
        .unwrap();
        let t2 = Probe::open(&(
            two.clone(),
            one.clone(),
            network.clone(),
        ))
        .unwrap();

        let a: u32 = 30303030;
        let b: u32 = 40404040;
        let timeout = Duration::from_millis(10);
        let h1 = thread::spawn(move || {
            dhke_handshake(&t1, timeout, a).unwrap()
        });
        let h2 = thread::spawn(move || {
            dhke_handshake(&t2, timeout, b).unwrap()
        });

        let s1 = h1.join().unwrap();
        let s2 = h2.join().unwrap();

        assert_eq!(s1, s2);
    }

    #[test]
    fn test_dfke_math() {
        let a: Int = 101010;
        let b: Int = 202020;

        let sent_a = modular_pow(BASE, a, MODULUS);
        let sent_b = modular_pow(BASE, b, MODULUS);

        let s1 = modular_pow(sent_a, b, MODULUS);
        let s2 = modular_pow(sent_b, a, MODULUS);

        assert_eq!(s1, s2);
    }
}
