//! Yet Another OAuth 1.0 Client Library for Rust

extern crate crypto;
extern crate rand;
extern crate rustc_serialize as serialize;
extern crate time;
extern crate url;

use std::ascii::AsciiExt;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt::{self, Write};
use std::mem;
use crypto::{hmac, sha1};
use crypto::mac::Mac;
use rand::Rng;
use serialize::base64::{self, ToBase64};
use url::{percent_encoding, Url};

/// Available `oauth_signature_method` types.
#[derive(Copy, Debug, PartialEq, Eq, Clone)]
pub enum SignatureMethod {
    /// HMAC-SHA1
    HmacSha1,
    /// PLAINTEXT
    Plaintext
}

impl fmt::Display for SignatureMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            SignatureMethod::HmacSha1 => "HMAC-SHA1",
            SignatureMethod::Plaintext => "PLAINTEXT"
        })
    }
}

static ENCODE_SET_MAP: &'static [&'static str; 256] = &[
    "%00", "%01", "%02", "%03", "%04", "%05", "%06", "%07",
    "%08", "%09", "%0A", "%0B", "%0C", "%0D", "%0E", "%0F",
    "%10", "%11", "%12", "%13", "%14", "%15", "%16", "%17",
    "%18", "%19", "%1A", "%1B", "%1C", "%1D", "%1E", "%1F",
    "%20", "%21", "%22", "%23", "%24", "%25", "%26", "%27",
    "%28", "%29", "%2A", "%2B", "%2C", "-", ".", "%2F",
    "0", "1", "2", "3", "4", "5", "6", "7",
    "8", "9", "%3A", "%3B", "%3C", "%3D", "%3E", "%3F",
    "%40", "A", "B", "C", "D", "E", "F", "G",
    "H", "I", "J", "K", "L", "M", "N", "O",
    "P", "Q", "R", "S", "T", "U", "V", "W",
    "X", "Y", "Z", "%5B", "%5C", "%5D", "%5E", "_",
    "%60", "a", "b", "c", "d", "e", "f", "g",
    "h", "i", "j", "k", "l", "m", "n", "o",
    "p", "q", "r", "s", "t", "u", "v", "w",
    "x", "y", "z", "%7B", "%7C", "%7D", "~", "%7F",
    "%80", "%81", "%82", "%83", "%84", "%85", "%86", "%87",
    "%88", "%89", "%8A", "%8B", "%8C", "%8D", "%8E", "%8F",
    "%90", "%91", "%92", "%93", "%94", "%95", "%96", "%97",
    "%98", "%99", "%9A", "%9B", "%9C", "%9D", "%9E", "%9F",
    "%A0", "%A1", "%A2", "%A3", "%A4", "%A5", "%A6", "%A7",
    "%A8", "%A9", "%AA", "%AB", "%AC", "%AD", "%AE", "%AF",
    "%B0", "%B1", "%B2", "%B3", "%B4", "%B5", "%B6", "%B7",
    "%B8", "%B9", "%BA", "%BB", "%BC", "%BD", "%BE", "%BF",
    "%C0", "%C1", "%C2", "%C3", "%C4", "%C5", "%C6", "%C7",
    "%C8", "%C9", "%CA", "%CB", "%CC", "%CD", "%CE", "%CF",
    "%D0", "%D1", "%D2", "%D3", "%D4", "%D5", "%D6", "%D7",
    "%D8", "%D9", "%DA", "%DB", "%DC", "%DD", "%DE", "%DF",
    "%E0", "%E1", "%E2", "%E3", "%E4", "%E5", "%E6", "%E7",
    "%E8", "%E9", "%EA", "%EB", "%EC", "%ED", "%EE", "%EF",
    "%F0", "%F1", "%F2", "%F3", "%F4", "%F5", "%F6", "%F7",
    "%F8", "%F9", "%FA", "%FB", "%FC", "%FD", "%FE", "%FF",
];

/// Return the EncodeSet of [RFC 5849 section 3.6](http://tools.ietf.org/html/rfc5849#section-3.6).
pub fn encode_set() -> percent_encoding::EncodeSet {
    unsafe { mem::transmute(ENCODE_SET_MAP) }
}

#[inline]
fn percent_encode(input: &str) -> String {
    percent_encoding::utf8_percent_encode(input, encode_set())
}

fn base_string_url(url: Url) -> String {
    let scheme = url.scheme.to_ascii_lowercase();
    assert!(match &scheme[..]
        { "http" => true, "https" => true, _ => false });
    let mut result = format!("{}://", scheme);
    match url.scheme_data {
        url::SchemeData::Relative(data) => {
            result.push_str(&data.host.to_string().to_ascii_lowercase()[..]);
            match data.port {
                Some(p) => if p != data.default_port.unwrap() {
                    write!(&mut result, ":{}", p).ok();
                 },
                 None => ()
            }
            result.push_str(&data.serialize_path()[..]);
        },
        url::SchemeData::NonRelative(_) => panic!("scheme_data is NonRelative")
    }
    result
}

fn normalize_parameters<P>(params: P) -> String
        where P: Iterator<Item = (String, String)> {
    let mut mutparams: Vec<_> = params
        .map(|x| (percent_encode(&x.0[..]), percent_encode(&x.1[..])))
        .collect();
    mutparams.sort_by(|a, b| {
        match a.0.cmp(&b.0) {
            Ordering::Less => Ordering::Less,
            Ordering::Equal => a.1.cmp(&b.1),
            Ordering::Greater => Ordering::Greater
        }
    });
    mutparams.sort();
    mutparams.iter()
        .map(|x| format!("{}={}", x.0, x.1))
        .collect::<Vec<String>>()
        .connect("&")
}

/// Generate a string for `oauth_timestamp`.
#[inline]
pub fn timestamp() -> String {
    time::now_utc().to_timespec().sec.to_string()
}

/// Generate a string for `oauth_nonce`.
#[inline]
pub fn nonce() -> String {
    rand::thread_rng()
        .gen_ascii_chars()
        .take(42)
        .collect()
}

#[inline]
fn oauth_parameters(realm: Option<&str>, consumer_key: &str,
        token: Option<&str>, signature_method: SignatureMethod,
        timestamp: String, nonce: String, callback: Option<&str>,
        verifier: Option<&str>)
        -> HashMap<&'static str, String> {
    let mut h = HashMap::new();
    match realm { Some(x) => { h.insert("realm", x.to_string()); }, None => () }
    h.insert("oauth_consumer_key", consumer_key.to_string());
    match token { Some(x) => { h.insert("oauth_token", x.to_string()); }, None => () }
    h.insert("oauth_signature_method", signature_method.to_string());
    h.insert("oauth_timestamp", timestamp);
    h.insert("oauth_nonce", nonce);
    match callback { Some(x) => { h.insert("oauth_callback", x.to_string()); }, None => () }
    match verifier { Some(x) => { h.insert("oauth_verifier", x.to_string()); }, None => () }
    // oauth_version is optional
    h
}

fn signature_base_string<P>(method: &str, url: Url,
        params: P, mut oauth_params: HashMap<&'static str, String>)
        -> String where P: Iterator<Item = (String, String)> {
    let mut mutparams: Vec<(String, String)> = params
        .map(|x| (x.0.clone(), x.1.clone())).collect();
    oauth_params.remove("realm");
    mutparams.extend(oauth_params.iter()
        .map(|(key, val)| (key.to_string(), val.clone())));
    let query = match url.query_pairs() {
        Some(pairs) => pairs,
        None => Vec::new()
    };
    mutparams.extend(query.iter().map(|x| (x.0.clone(), x.1.clone())));
    format!(
        "{}&{}&{}",
        method.to_ascii_uppercase(),
        percent_encode(&base_string_url(url)[..]),
        percent_encode(&normalize_parameters(mutparams.into_iter())[..])
    )
}

fn signature(base_string: String, signature_method: SignatureMethod,
        consumer_secret: &str, token_secret: Option<&str>) -> String {
    let ts = match token_secret {
        Some(x) => percent_encode(x),
        None => "".to_string()
    };
    let key = format!("{}&{}", percent_encode(consumer_secret), ts);
    match signature_method {
        SignatureMethod::HmacSha1 => {
            let mut h = hmac::Hmac::new(sha1::Sha1::new(), key.as_bytes());
            h.input(base_string.as_bytes());
            h.result().code().to_base64(base64::Config {
                char_set: serialize::base64::CharacterSet::Standard,
                newline: serialize::base64::Newline::LF,
                pad: true,
                line_length: None
            })
        },
        SignatureMethod::Plaintext => key
    }
}

/// Generate OAuth parameters set.
/// The return value contains elements whose key is `"oauth_foo"`.
pub fn protocol_parameters<P>(method: &str, url: Url, realm: Option<&str>,
        consumer_key: &str, consumer_secret: &str, token: Option<&str>,
        token_secret: Option<&str>, signature_method: SignatureMethod,
        timestamp: String, nonce: String, callback: Option<&str>,
        verifier: Option<&str>, params: P)
        -> HashMap<&'static str, String>
        where P: Iterator<Item = (String, String)> {
    let mut oauth_params = oauth_parameters(
        realm, consumer_key, token, signature_method, timestamp, nonce,
        callback, verifier);
    let tmp = oauth_params.clone();
    oauth_params.insert("oauth_signature", signature(
        signature_base_string(method, url, params, tmp),
        signature_method, consumer_secret, token_secret
    ));
    oauth_params
}


/// Generate `Authorization` header for OAuth.
/// The return value starts with `"OAuth "`.
pub fn authorization_header<P>(method: &str, url: Url, realm: Option<&str>,
        consumer_key: &str, consumer_secret: &str, token: Option<&str>,
        token_secret: Option<&str>, signature_method: SignatureMethod,
        timestamp: String, nonce: String, callback: Option<&str>,
        verifier: Option<&str>, params: P)
        -> String
        where P: Iterator<Item = (String, String)> {
    let p = protocol_parameters(method, url, realm, consumer_key, consumer_secret,
        token, token_secret, signature_method, timestamp, nonce, callback, verifier, params);
    format!("OAuth {}", p.iter()
        .map(|(key, val)| format!("{}=\"{}\"",
            percent_encode(*key), percent_encode(&val[..])))
        .collect::<Vec<String>>()
        .connect(",")
    )
}

#[cfg(test)]
mod tests;
