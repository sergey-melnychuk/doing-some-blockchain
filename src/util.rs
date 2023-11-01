pub fn crc32(xs: &[u8]) -> u32 {
    use crc32fast::Hasher;
    let mut hasher = Hasher::new();
    hasher.update(xs);
    hasher.finalize()
}

pub fn time() -> u32 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

pub fn random() -> u32 {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    rng.gen()
}

pub fn split(x: u64) -> (u32, u32) {
    let lo = (x & u32::MAX as u64) as u32;
    let hi = (x >> 32) as u32;
    (hi, lo)
}

pub fn merge(hi: u32, lo: u32) -> u64 {
    let mut x = hi as u64;
    x <<= 32;
    x |= lo as u64;
    x
}

#[cfg(test)]
mod tests {
    use super::{merge, split};

    #[test]
    fn test_split() {
        assert_eq!(
            split(0xCAFEBABEBEEFFACE),
            (0xCAFEBABE, 0xBEEFFACE)
        );
    }

    #[test]
    fn test_merge() {
        assert_eq!(
            merge(0xCAFEBABE, 0xBEEFFACE),
            0xCAFEBABEBEEFFACE
        );
    }
}
