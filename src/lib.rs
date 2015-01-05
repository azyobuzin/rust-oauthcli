//! Implementation of OAuth 1.0 Client

extern crate core;
extern crate time;
extern crate url;

use core::cmp::Ordering;
use std::ascii::AsciiExt;
use std::collections::HashMap;
use std::rand::{self, Rng};
use url::percent_encoding;

#[inline]
fn percent_encode(input: &str) -> String {
    // ALPHA, DIGIT, '-', '.', '_', '~'
    percent_encoding::utf8_percent_encode(
        input,
        percent_encoding::FORM_URLENCODED_ENCODE_SET
    )
}

fn base_string_uri(uri: url::Url) -> String {
    let scheme = uri.scheme.to_ascii_lowercase();
    assert!(match scheme.as_slice()
        { "http" => true, "https" => true, _ => false });
    let mut result = scheme.clone();
    result.push_str("://");
    match uri.scheme_data {
        url::SchemeData::Relative(data) => {
            result.push_str(data.host.to_string().to_ascii_lowercase().as_slice());
            match data.port {
                Some(p) => {
                    if p != data.default_port.unwrap() {
                        result.push(':');
                        result.push_str(p.to_string().as_slice());
                    }
                 },
                 None => { }
            }
            result.push_str(data.serialize_path().as_slice());
        },
        url::SchemeData::NonRelative(_) => panic!("scheme_data is NonRelative")
    }
    result
}

fn normalize_parameters<'a, P>(params: P) -> String
        where P: Iterator<Item = (&'a str, &'a str)> {
    let mut mutparams: Vec<_> = params
        .map(|x| (percent_encode(x.0), percent_encode(x.1)))
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

fn timestamp() -> String {
    time::now_utc().to_timespec().sec.to_string()
}

fn nonce() -> String {
    rand::thread_rng()
        .gen_ascii_chars()
        .take(42)
        .collect()
}

fn oauth_parameters<'a>(realm: Option<&'a str>, consumer_key: &'a str,
        token: Option<&'a str>, timestamp: &'a str, nonce: &'a str,
        callback: Option<&'a str>, verifier: Option<&'a str>)
        -> HashMap<&'a str, &'a str> {
    let mut h = HashMap::<&'a str, &'a str>::new();
    match realm { Some(x) => { h.insert("realm", x); }, None => { } }
    h.insert("oauth_consumer_key", consumer_key);
    match token { Some(x) => { h.insert("oauth_token", x); }, None => { } }
    h.insert("oauth_signature_method", "HMAC-SHA1"); // want PLAINTEXT?
    h.insert("oauth_timestamp", timestamp);
    h.insert("oauth_nonce", nonce);
    match callback { Some(x) => { h.insert("oauth_callback", x); }, None => { } }
    match verifier { Some(x) => { h.insert("oauth_verifier", x); }, None => { } }
    h
}

fn signature_base_string<'a, P>(method: &'a str, uri: url::Url,
        params: P, oauth_params: HashMap<&'a str, &'a str>)
        -> String where P: Iterator<Item = (&'a str, &'a str)> {
    let mut mutparams: Vec<(&'a str, &'a str)> = params.collect();
    for (key, val) in oauth_params.iter() {
        mutparams.push((*key, *val))
    }
    [method.to_ascii_uppercase(), percent_encode(base_string_uri(uri).as_slice()),
        percent_encode(normalize_parameters(mutparams.into_iter()).as_slice())].connect("&")
}

#[cfg(test)]
mod tests;
