use url::Url;
use super::{percent_encode, base_string_uri, normalize_parameters};

#[test]
fn percent_encode_test() {
    assert_eq!(
        percent_encode("Ladies + Gentlemen").as_slice(),
        "Ladies%20%2B%20Gentlemen"
    );
    assert_eq!(
        percent_encode("An encoded string!").as_slice(),
        "An%20encoded%20string%21"
    );
    assert_eq!(
        percent_encode("Dogs, Cats & Mice").as_slice(),
        "Dogs%2C%20Cats%20%26%20Mice"
    );
    assert_eq!(
        percent_encode("☃").as_slice(),
        "%E2%98%83"
    );
}

#[test]
fn base_string_uri_test() {
    assert_eq!(
        base_string_uri(
            Url::parse("HTTP://EXAMPLE.COM:80/r%20v/X?id=123").unwrap()
        ).as_slice(),
        "http://example.com/r%20v/X"
    );
    assert_eq!(
        base_string_uri(
            Url::parse("https://www.example.net:8080/?q=1").unwrap()
        ).as_slice(),
        "https://www.example.net:8080/"
    );
}

const PARAMS: [(&'static str, &'static str); 11] = [
    ("b5", "=%3D"),
    ("a3", "a"),
    ("c@", ""),
    ("a2", "r b"),
    ("oauth_consumer_key", "9djdj82h48djs9d2"),
    ("oauth_token", "kkk9d7dh3k39sjv7"),
    ("oauth_signature_method", "HMAC-SHA1"),
    ("oauth_timestamp", "137131201"),
    ("oauth_nonce", "7d8f3e4a"),
    ("c2", ""),
    ("a3", "2 q")
];

#[test]
fn normalize_parameters_test() {
    assert_eq!(
        normalize_parameters(PARAMS.iter().map(|x| *x)).as_slice(),
        concat!(
            "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9dj",
            "dj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1",
            "&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7"
        )
    );
}

#[test]
fn signature_base_string_test() {
    //TODO
}
