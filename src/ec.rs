use crate::util::crc32;

#[derive(Debug)]
pub struct SecretKey(u32);

#[derive(Debug)]
pub struct PublicKey(u32, u32);

#[derive(Debug)]
pub struct Signature(u32, u32);

impl SecretKey {
    pub fn new(secret: u32) -> Self {
        Self(secret)
    }

    pub fn public_key(&self) -> PublicKey {
        let (x, y) = mul(self.0 as curve::Int, curve::G);
        PublicKey(x as u32, y as u32)
    }

    pub fn sign(&self, msg: &u32) -> Signature {
        let h = crc32(&msg.to_be_bytes());
        let k = crc32(
            h.to_be_bytes()
                .into_iter()
                .chain(
                    crc32(&self.0.to_be_bytes()).to_be_bytes(),
                )
                .collect::<Vec<_>>()
                .as_ref(),
        );
        let h = h as curve::Int;
        let k = k as curve::Int;

        let r = mul(k, curve::G).0;

        let k_inv = modular_inv(k);
        let key = self.0 as curve::Int;
        let s = k_inv * (h + r * key) % curve::M;

        println!("sig: msg={msg} h={h} r={r} k={k} k'={k_inv} key={key} s={s}");
        Signature(r as u32, s as u32)
    }
}

impl PublicKey {
    pub fn is_valid(&self, msg: &u32, sig: &Signature) -> bool {
        let h = crc32(&msg.to_be_bytes()) as curve::Int;
        let (r, s) = (sig.0, sig.1);
        let r = r as curve::Int;
        let s_inv = modular_inv(s as curve::Int);

        let a = mul(h * s_inv, curve::G);
        let b = mul(
            r * s_inv,
            (self.0 as curve::Int, self.1 as curve::Int),
        );
        let p = add(a, b);

        println!(
            "ver: r={r} s={s} s'={s_inv} h={h} LHS={a:?} RHS={b:?} SUM={p:?}"
        );
        p.0 == r
    }
}

pub mod curve {
    // (y^2) % M = (x^3 + a*x + b) % M

    pub type Int = i128;
    pub type Point = (Int, Int);

    // pub const M: Int = 4224215813;
    // pub const A: Int = 3357810478;
    // pub const B: Int = 1876092379;
    // pub const G: (Int, Int) = (42887013, 2256698221);

    pub const M: Int = 2267;
    pub const A: Int = 1600;
    pub const B: Int = 1384;
    pub const G: (Int, Int) = (2056, 1998);
}

pub fn extended_gcd(a: curve::Int, p: curve::Int) -> curve::Int {
    if a == 0 {
        panic!("division by zero");
    }
    if a < 0 {
        return p - extended_gcd(-a, p);
    };

    let mut old_r = a;
    let mut r = p;
    let mut old_s: curve::Int = 1;
    let mut s: curve::Int = 0;

    #[allow(unused_assignments)]
    let mut x = 0;
    while r != 0 {
        let quotient = old_r / r;

        x = r;
        r = old_r - quotient * r;
        old_r = x;

        x = s;
        s = old_s - quotient * s;
        old_s = x;
    }

    let gcp = old_r;
    assert_eq!(gcp, 1);

    x = old_s % p;
    x = if x > 0 { x } else { p + x };
    assert!(x > 0);
    assert_eq!((a * x) % p, 1);

    x
}

pub fn modular_inv(x: curve::Int) -> curve::Int {
    extended_gcd(x, curve::M)
}

pub fn fits(p: curve::Point) -> bool {
    use curve::*;
    let (x, y) = p;

    let lhs = (y.pow(2)) % M;
    let rhs = (x.pow(3) + A * x + B) % M;

    lhs == rhs
}

pub fn add(p: curve::Point, q: curve::Point) -> curve::Point {
    use curve::*;
    let (px, py) = p;
    let (qx, qy) = q;

    let d = if px == qx {
        let z = modular_inv(2 * py);
        (3 * px * px + A) * z // "attempt to multiply with overflow"
    } else {
        let z = modular_inv(qx - px);
        (qy - py) * z
    };

    let x = d * d - px - qx;
    let y = d * (px - x) - py;

    {
        let x = x % M;
        let y = y % M;
        let lhs = (y * y) % M;
        let rhs = (x * x * x + A * x + B) % M;
        assert!(lhs == rhs);
    }

    (x, y)
}

pub fn mul(mut k: curve::Int, p: curve::Point) -> curve::Point {
    let mut r = None;
    let mut p = p;

    while k > 0 {
        if k % 2 > 0 {
            r = match r {
                Some(r) => Some(add(r, p)),
                None => Some(p),
            };
        }
        p = add(p, p);
        k >>= 2;
    }

    let r = r.unwrap_or(p);
    assert!(fits(r));
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve::*;

    #[test]
    fn text_mod_inv() {
        fn check(a: Int, b: Int) -> bool {
            (a * b) % M == 1
        }

        for a in [12345, 123456, 1234567] {
            let x = modular_inv(a);
            assert!(check(a, x));
        }
    }

    #[test]
    #[ignore = "'attempt to multiply with overflow'"]
    fn test_math() {
        let g = curve::G;
        assert!(fits(g));

        assert_eq!(mul(1, g), g);
        assert_eq!(mul(2, g), add(g, g));

        assert_eq!(add(add(g, g), g), add(g, add(g, g)));
        assert_eq!(mul(3, g), add(g, add(g, g)));
        assert_eq!(mul(3, g), add(add(g, g), g));
        assert_eq!(mul(4, g), add(add(g, g), add(g, g)));

        for (a, b) in [(1, 1), (101, 202)] {
            let x = add(mul(a, g), mul(b, g));
            let y = mul(a + b, g);
            assert_eq!(x, y, "[a={b} b={b}] {x:?} != {y:?}");
        }
    }

    #[test]
    #[ignore = "'attempt to multiply with overflow'"]
    fn test_sign() {
        let secret = u32::from_be_bytes(*b"LOL!");
        let secret_key = SecretKey::new(secret);
        let public_key = secret_key.public_key();

        let msg = 0xCAFEBABEu32;
        let sig = secret_key.sign(&msg);
        assert!(
            public_key.is_valid(&msg, &sig),
            "false negative: invalid signature"
        );
    }
}
