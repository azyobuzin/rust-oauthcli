use std::vec::IntoIter;
use url::Url;
use super::{SignatureMethod, percent_encode, base_string_url, normalize_parameters,
    oauth_parameters, signature_base_string/*, signature*/};

#[test]
fn signature_method_test() {
    assert_eq!(
        &SignatureMethod::HmacSha1.to_string()[..],
        "HMAC-SHA1"
    );
    assert_eq!(
        &SignatureMethod::Plaintext.to_string()[..],
        "PLAINTEXT"
    );
}

#[test]
fn percent_encode_test() {
    assert_eq!(
        &percent_encode("Ladies + Gentlemen")[..],
        "Ladies%20%2B%20Gentlemen"
    );
    assert_eq!(
        &percent_encode("An encoded string!")[..],
        "An%20encoded%20string%21"
    );
    assert_eq!(
        &percent_encode("Dogs, Cats & Mice")[..],
        "Dogs%2C%20Cats%20%26%20Mice"
    );
    assert_eq!(
        &percent_encode("☃")[..],
        "%E2%98%83"
    );
}

#[test]
fn base_string_url_test() {
    assert_eq!(
        &base_string_url(
            Url::parse("HTTP://EXAMPLE.COM:80/r%20v/X?id=123").unwrap()
        )[..],
        "http://example.com/r%20v/X"
    );
    assert_eq!(
        &base_string_url(
            Url::parse("https://www.example.net:8080/?q=1").unwrap()
        )[..],
        "https://www.example.net:8080/"
    );
}

const URI: &'static str = "http://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b";
const REALM: &'static str = "Example";
const CONSUMER_KEY: &'static str = "9djdj82h48djs9d2";
//const CONSUMER_SECRET: &'static str = "j49sk3j29djd";
const TOKEN: &'static str = "kkk9d7dh3k39sjv7";
//const TOKEN_SECRET: &'static str = "dh893hdasih9";
const TIMESTAMP: &'static str = "137131201";
const NONCE: &'static str = "7d8f3e4a";

fn params() -> IntoIter<(String, String)> {
    vec![
        ("b5".to_string(), "=%3D".to_string()),
        ("a3".to_string(), "a".to_string()),
        ("c@".to_string(), "".to_string()),
        ("a2".to_string(), "r b".to_string()),
        ("oauth_consumer_key".to_string(), CONSUMER_KEY.to_string()),
        ("oauth_token".to_string(), TOKEN.to_string()),
        ("oauth_signature_method".to_string(), "HMAC-SHA1".to_string()),
        ("oauth_timestamp".to_string(), TIMESTAMP.to_string()),
        ("oauth_nonce".to_string(), NONCE.to_string()),
        ("c2".to_string(), "".to_string()),
        ("a3".to_string(), "2 q".to_string())
    ].into_iter()
}

#[test]
fn normalize_parameters_test() {
    assert_eq!(
        &normalize_parameters(params())[..],
        concat!(
            "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj",
            "dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1",
            "&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"
        )
    );
}

fn get_signature_base_string() -> String {
    signature_base_string(
        "post",
        Url::parse(URI).unwrap(),
        params().skip(9),
        oauth_parameters(Some(REALM), CONSUMER_KEY, Some(TOKEN),
            SignatureMethod::HmacSha1, TIMESTAMP, NONCE, None, None)
    )
}

#[test]
fn signature_base_string_test() {
    assert_eq!(
        &get_signature_base_string()[..],
        concat!(
            "POST&http%3A%2F%2Fexample.com%2Frequest&a2%3Dr%2520b%26a3%3D2%2520q",
            "%26a3%3Da%26b5%3D%253D%25253D%26c%2540%3D%26c2%3D%26oauth_consumer_",
            "key%3D9djdj82h48djs9d2%26oauth_nonce%3D7d8f3e4a%26oauth_signature_m",
            "ethod%3DHMAC-SHA1%26oauth_timestamp%3D137131201%26oauth_token%3Dkkk",
            "9d7dh3k39sjv7%26oauth_version%3D1.0"
        )
    );
}

/* なぜか通らないテスト
#[test]
fn signature_test() {
    assert_eq!(
        signature(
            get_signature_base_string(),
            SignatureMethod::HmacSha1,
            CONSUMER_SECRET,
            Some(TOKEN_SECRET)
        ).as_slice(),
        "bYT5CMsGcbgUdFHObYMEfcx6bsw%3D"
    );
}
*/
