//! Implementation of OAuth Core 1.0A Client

extern crate url;
use url::percent_encoding;

fn percent_encode(input: &str) -> String {
    // ALPHA, DIGIT, '-', '.', '_', '~'
    percent_encoding::utf8_percent_encode(
        input,
        percent_encoding::FORM_URLENCODED_ENCODE_SET
    )
}

#[test]
fn percent_encode_test() {
    // https://dev.twitter.com/oauth/overview/percent-encoding-parameters
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
