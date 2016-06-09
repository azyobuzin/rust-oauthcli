//! Yet Another OAuth 1.0 Client Library for Rust

extern crate crypto;
extern crate rand;
extern crate rustc_serialize as serialize;
extern crate time;
pub extern crate url;

use std::ascii::AsciiExt;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt::{self, Write};
use crypto::{hmac, sha1};
use crypto::mac::Mac;
use rand::Rng;
use serialize::base64::{self, ToBase64};
use url::{percent_encoding, Host, Url};

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

/// [RFC 5849 section 3.6](http://tools.ietf.org/html/rfc5849#section-3.6).
#[derive(Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct OAUTH_ENCODE_SET;

impl percent_encoding::EncodeSet for OAUTH_ENCODE_SET {
    fn contains(&self, byte: u8) -> bool {
        !((byte >= 0x30 && byte <= 0x39)
        || (byte >= 0x41 && byte <= 0x5A)
        || (byte >= 0x61 && byte <= 0x7A)
        || byte == 0x2D || byte == 0x2E
        || byte == 0x5F || byte == 0x7E)
    }
}

#[inline]
fn percent_encode(input: &str) -> String {
    percent_encoding::utf8_percent_encode(input, OAUTH_ENCODE_SET)
        .collect::<String>()
}

fn base_string_url(url: Url) -> String {
    let scheme = url.scheme().to_ascii_lowercase();
    assert!(match &scheme[..]
        { "http" | "https" => true, _ => false });
    let mut result = format!("{}://", scheme);
    match url.host() {
        Some(Host::Domain(host)) => {
            result.push_str(&host.to_ascii_lowercase()[..]);
        },
        _ => panic!("Invalid host")
    }
    match url.port() {
        Some(p) => match (&scheme[..], p) {
            ("http", 80) | ("https", 443) => (),
            _ => { write!(&mut result, ":{}", p).ok(); }
        },
        None => ()
    }
    result.push_str(&url.path()[..]);
    result
}

fn normalize_parameters<P>(params: P) -> String
    where P: Iterator<Item = (String, String)>
{
    let mut mutparams: Vec<_> = params
        .map(|x| (percent_encode(&x.0[..]), percent_encode(&x.1[..])))
        .collect();
    mutparams.sort_by(|a, b| {
        match a.0.cmp(&b.0) {
            Ordering::Equal => a.1.cmp(&b.1),
            x => x
        }
    });
    let mut result = String::new();
    if mutparams.len() > 0 {
        let mut first = true;
        for (key, val) in mutparams.into_iter() {
            if first { first = false; }
            else { result.push('&'); }
            write!(&mut result, "{}={}", key, val).ok();
        }
    }
    result
}

/// Generate a string for `oauth_timestamp`.
#[inline]
pub fn timestamp() -> String {
    time::now_utc().to_timespec().sec.to_string()
}

/// Generate a string for `oauth_nonce`.
#[inline]
pub fn nonce() -> String {
    rand::thread_rng().gen_ascii_chars()
        .take(42).collect()
}

#[inline]
fn oauth_parameters(realm: Option<&str>, consumer_key: &str,
    token: Option<&str>, signature_method: SignatureMethod,
    timestamp: &str, nonce: &str, callback: Option<&str>,
    verifier: Option<&str>)
    -> HashMap<&'static str, String>
{
    let mut h = HashMap::new();
    match realm { Some(x) => { h.insert("realm", x.to_string()); }, None => () }
    h.insert("oauth_consumer_key", consumer_key.to_string());
    match token { Some(x) => { h.insert("oauth_token", x.to_string()); }, None => () }
    h.insert("oauth_signature_method", signature_method.to_string());
    h.insert("oauth_timestamp", timestamp.to_string());
    h.insert("oauth_nonce", nonce.to_string());
    match callback { Some(x) => { h.insert("oauth_callback", x.to_string()); }, None => () }
    match verifier { Some(x) => { h.insert("oauth_verifier", x.to_string()); }, None => () }
    h.insert("oauth_version", "1.0".to_string());
    h
}

fn signature_base_string<P>(method: &str, url: Url,
    params: P, mut oauth_params: HashMap<&'static str, String>)
    -> String where P: Iterator<Item = (String, String)>
{
    let mut mutparams: Vec<(String, String)> = params
        .map(|x| (x.0.clone(), x.1.clone())).collect();
    oauth_params.remove("realm");
    mutparams.extend(oauth_params.iter()
        .map(|(key, val)| (key.to_string(), val.clone())));
    mutparams.extend(url.query_pairs().map(|x| (x.0.to_string(), x.1.to_string())));
    format!(
        "{}&{}&{}",
        method.to_ascii_uppercase(),
        percent_encode(&base_string_url(url)[..]),
        percent_encode(&normalize_parameters(mutparams.into_iter())[..])
    )
}

fn signature(base_string: String, signature_method: SignatureMethod,
    consumer_secret: &str, token_secret: Option<&str>) -> String
{
    let ts = match token_secret {
        Some(x) => percent_encode(x),
        None => String::new()
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
    timestamp: &str, nonce: &str, callback: Option<&str>,
    verifier: Option<&str>, params: P)
    -> HashMap<&'static str, String>
    where P: Iterator<Item = (String, String)>
{
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
    timestamp: &str, nonce: &str, callback: Option<&str>,
    verifier: Option<&str>, params: P)
    -> String where P: Iterator<Item = (String, String)>
{
    let p = protocol_parameters(method, url, realm, consumer_key, consumer_secret,
        token, token_secret, signature_method, timestamp, nonce, callback, verifier, params);
    let mut result = "OAuth ".to_string();
    if p.len() > 0 {
        let mut first = true;
        for (&key, val) in p.iter() {
            if first { first = false; }
            else { result.push(','); }
            write!(&mut result, "{}=\"{}\"",
                percent_encode(key), percent_encode(&val[..])).ok();
        }
    }
    result
}

#[cfg(test)]
mod tests;
