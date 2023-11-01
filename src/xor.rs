pub fn split(s: u32, n: usize, f: impl Fn() -> u32) -> Vec<u32> {
    let mut ret: Vec<u32> = (0..n).map(|_| f()).collect();
    let acc = ret
        .iter()
        .skip(1)
        .cloned()
        .reduce(|a, b| a ^ b)
        .unwrap_or_default();
    ret[0] = s ^ acc;
    ret
}

pub fn merge(shares: &[u32]) -> u32 {
    let mut ret = 0u32;
    for share in shares {
        ret ^= share;
    }
    ret
}

#[cfg(test)]
mod tests {
    use crate::util::random;

    use super::*;

    #[test]
    fn test_split_merge() {
        let secret = 0xCAFEBABE;
        let n = 10;
        let shares = split(secret, n, || random());
        assert_eq!(merge(&shares), secret);
    }

    #[test]
    fn test_refresh() {
        let secret = 0xCAFEBABE;
        let k = random() as usize % 10;
        let n = k * 2; // works only with even number of shares
        let mut shares = split(secret, n, || random());

        let r = random();
        shares.iter_mut().for_each(|s| *s ^= r);

        assert_eq!(merge(&shares), secret);
    }
}
