use std::iter;
use std::num::Wrapping;

pub trait HashAlgorithm {
    type Output: AsRef<[u8]>;
    fn block_size(&self) -> usize;
    fn compute_hash(&self, input: &[u8]) -> Self::Output;
}

pub struct Sha1;

impl HashAlgorithm for Sha1 {
    type Output = [u8; 20];

    fn block_size(&self) -> usize {
        64
    }

    fn compute_hash(&self, input: &[u8]) -> Self::Output {
        let ml_bytes = {
            let ml = (input.len() as u64) * 8;
            [
                (ml >> 56) as u8,
                (ml >> 48) as u8,
                (ml >> 40) as u8,
                (ml >> 32) as u8,
                (ml >> 24) as u8,
                (ml >> 16) as u8,
                (ml >> 8) as u8,
                ml as u8
            ]
        };

        let padding = 64 - ((input.len() + 9) % 64);

        let mut msg = input.iter()
            .map(|x| *x)
            .chain(iter::once(0x80u8))
            .chain(iter::repeat(0u8).take(padding))
            .chain(ml_bytes.into_iter().map(|x| *x));

        let mut w = [Default::default(); 80];

        // (The length of msg + 63) / 64
        let (h0, h1, h2, h3, h4) = (0..((input.len() + padding + 64) / 64)).fold(
            (Wrapping(0x67452301u32), Wrapping(0xEFCDAB89u32), Wrapping(0x98BADCFEu32), Wrapping(0x10325476u32), Wrapping(0xC3D2E1F0u32)),
            move |(h0, h1, h2, h3, h4), _|
            {
                for t in 0..16 {
                    w[t] = Wrapping(
                        ((msg.next().unwrap() as u32) << 24) |
                        ((msg.next().unwrap() as u32) << 16) |
                        ((msg.next().unwrap() as u32) << 8) |
                        (msg.next().unwrap() as u32)
                    );
                }

                for t in 16..80 {
                    w[t] = Wrapping((w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).0.rotate_left(1));
                }

                let (a, b, c, d, e) = (0..80).fold(
                    (h0, h1, h2, h3, h4),
                    |(a, b, c, d, e), t| {
                        let f =
                            if t < 20 { ((b & c) | (!b & d)) + Wrapping(0x5A827999) }
                            else if t < 40 { (b ^ c ^ d) + Wrapping(0x6ED9EBA1) }
                            else if t < 60 { ((b & c) | (b & d) | (c & d)) + Wrapping(0x8F1BBCDC) }
                            else { (b ^ c ^ d) + Wrapping(0xCA62C1D6) };

                        (Wrapping(a.0.rotate_left(5)) + f + e + w[t], a, Wrapping(b.0.rotate_left(30)), c, d)
                    }
                );

                (h0 + a, h1 + b, h2 + c, h3 + d, h4 + e)
            }
        );

        [
            (h0.0 >> 24) as u8, (h0.0 >> 16) as u8, (h0.0 >> 8) as u8, h0.0 as u8,
            (h1.0 >> 24) as u8, (h1.0 >> 16) as u8, (h1.0 >> 8) as u8, h1.0 as u8,
            (h2.0 >> 24) as u8, (h2.0 >> 16) as u8, (h2.0 >> 8) as u8, h2.0 as u8,
            (h3.0 >> 24) as u8, (h3.0 >> 16) as u8, (h3.0 >> 8) as u8, h3.0 as u8,
            (h4.0 >> 24) as u8, (h4.0 >> 16) as u8, (h4.0 >> 8) as u8, h4.0 as u8
        ]
    }
}

pub fn hmac<H: HashAlgorithm>(key: &[u8], msg: &[u8], hash: H) -> H::Output {
    let block_size = hash.block_size();
    let tmp_key;
    let key =
        if key.len() > block_size {
            tmp_key = hash.compute_hash(key);
            tmp_key.as_ref()
        } else {
            key
        };

    let padding = block_size - key.len();

    let mut inner = Vec::with_capacity(block_size + msg.len());
    inner.extend(key.iter().map(|&x| x ^ 0x36).chain(iter::repeat(0x36).take(padding)));
    inner.extend_from_slice(msg);

    let inner_hash = hash.compute_hash(&inner);
    let inner_hash_ref = inner_hash.as_ref();

    let mut outer = Vec::with_capacity(block_size + inner_hash_ref.len());
    outer.extend(key.iter().map(|&x| x ^ 0x5C).chain(iter::repeat(0x5C).take(padding)));
    outer.extend_from_slice(inner_hash_ref);

    hash.compute_hash(&outer)
}

#[cfg(test)]
mod tests {
    use security::*;
    use serialize::hex::{FromHex, ToHex};
    fn from_hex(x: &str) -> Vec<u8> { x.from_hex().unwrap() }

    #[test]
    fn sha1_test() {
        assert_eq!(
            Sha1.compute_hash(&[0u8; 0]).to_hex(),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );

        assert_eq!(
            Sha1.compute_hash("The quick brown fox jumps over the lazy dog".as_bytes()).to_hex(),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }

    #[test]
    fn hmac_sha1_test() {
        fn hs(key: &[u8], msg: &[u8]) -> String { hmac(key, msg, Sha1).to_hex() }

        // https://www.ipa.go.jp/security/rfc/RFC2202JA.html

        assert_eq!(
            hs(&[0x0b; 20], "Hi There".as_bytes()),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );

        assert_eq!(
            hs("Jefe".as_bytes(), "what do ya want for nothing?".as_bytes()),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );

        assert_eq!(
            hs(&[0xaa; 20], &[0xddu8; 50]),
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        );

        assert_eq!(
            hs(&from_hex("0102030405060708090a0b0c0d0e0f10111213141516171819"), &[0xcd; 50]),
            "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
        );

        assert_eq!(
            hs(&[0x0c; 20], "Test With Truncation".as_bytes()),
            "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
        );

        assert_eq!(
            hs(&[0xaa; 80], "Test Using Larger Than Block-Size Key - Hash Key First".as_bytes()),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );

        assert_eq!(
            hs(&[0xaa; 80], "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".as_bytes()),
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
        );
    }
}