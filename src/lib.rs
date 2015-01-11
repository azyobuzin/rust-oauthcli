//! Implementation of OAuth 1.0 Client

extern crate crypto;
extern crate serialize;
extern crate time;
extern crate url;

use std::ascii::{AsciiExt, OwnedAsciiExt};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::rand::{self, Rng};
use crypto::{hmac, sha1};
use crypto::mac::Mac;
use serialize::base64::{self, ToBase64};
use url::{percent_encoding, Url};

pub enum SignatureMethod {
    HmacSha1,
    Plaintext
}
impl Copy for SignatureMethod { }

impl fmt::String for SignatureMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SignatureMethod::HmacSha1 => "HMAC-SHA1",
            SignatureMethod::Plaintext => "PLAINTEXT"
        }.fmt(f)
    }
}

#[inline]
fn percent_encode(input: &str) -> String {
    // ALPHA, DIGIT, '-', '.', '_', '~'
    percent_encoding::utf8_percent_encode(
        input,
        percent_encoding::FORM_URLENCODED_ENCODE_SET
    )
}

fn base_string_url(url: Url) -> String {
    let scheme = url.scheme.into_ascii_lowercase();
    assert!(match scheme.as_slice()
        { "http" => true, "https" => true, _ => false });
    let mut result = format!("{}://", scheme);
    match url.scheme_data {
        url::SchemeData::Relative(data) => {
            result.push_str(data.host.to_string().into_ascii_lowercase().as_slice());
            match data.port {
                Some(p) => {
                    if p != data.default_port.unwrap() {
                        result.push(':');
                        result.push_str(p.to_string().as_slice());
                    }
                 },
                 None => ()
            }
            result.push_str(data.serialize_path().as_slice());
        },
        url::SchemeData::NonRelative(_) => panic!("scheme_data is NonRelative")
    }
    result
}

fn normalize_parameters<'a, P>(params: P) -> String
        where P: Iterator<Item = &'a (String, String)> {
    let mut mutparams: Vec<_> = params
        .map(|x| (percent_encode(x.0.as_slice()), percent_encode(x.1.as_slice())))
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

#[inline]
pub fn timestamp() -> String {
    time::now_utc().to_timespec().sec.to_string()
}

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

fn signature_base_string<'a, P>(method: &str, url: Url,
        params: P, mut oauth_params: HashMap<&'static str, String>)
        -> String where P: Iterator<Item = &'a (String, String)> {
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
        percent_encode(base_string_url(url).as_slice()),
        percent_encode(normalize_parameters(mutparams.iter()).as_slice())
    )
}

fn signature<'a>(base_string: String, signature_method: SignatureMethod,
        consumer_secret: &str, token_secret: Option<&str>) -> String {
    let ts = match token_secret {
        Some(x) => percent_encode(x.as_slice()),
        None => "".to_string()
    };
    let key = format!("{}&{}", percent_encode(consumer_secret.as_slice()), ts);
    println!("{}", base_string);
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

pub fn protocol_parameters<'a, P>(method: &str, url: Url, realm: Option<&str>,
        consumer_key: &str, consumer_secret: &str, token: Option<&str>,
        token_secret: Option<&str>, signature_method: SignatureMethod,
        timestamp: String, nonce: String, callback: Option<&str>,
        verifier: Option<&str>, params: P)
        -> HashMap<&'static str, String>
        where P: Iterator<Item = &'a (String, String)> {
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

pub fn authorization_header<'a, P>(method: &str, url: Url, realm: Option<&str>,
        consumer_key: &str, consumer_secret: &str, token: Option<&str>,
        token_secret: Option<&str>, signature_method: SignatureMethod,
        timestamp: String, nonce: String, callback: Option<&str>,
        verifier: Option<&str>, params: P)
        -> String
        where P: Iterator<Item = &'a (String, String)> {
    let p = protocol_parameters(method, url, realm, consumer_key, consumer_secret,
        token, token_secret, signature_method, timestamp, nonce, callback, verifier, params);
    format!("OAuth {}", p.iter()
        .map(|(key, val)| format!("{}=\"{}\"",
            percent_encode(*key), percent_encode(val.as_slice())))
        .collect::<Vec<String>>()
        .connect(",")
    )
}

#[cfg(test)]
mod tests;
