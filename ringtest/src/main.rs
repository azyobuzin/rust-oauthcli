extern crate oauthcli;
extern crate ring;
extern crate url;

fn main() {
    use url::Url;
    use oauthcli::{OAuthAuthorizationHeaderBuilder, SignatureMethod};

    let url = Url::parse("https://api.twitter.com/1.1/statuses/user_timeline.json?screen_name=azyobuzin").unwrap();

    // @imgazyobuzi readonly token
    let auth_header = OAuthAuthorizationHeaderBuilder::new(
        "GET", &url, "uiYQy5R2RJFZRZ4zvSk7A", "qzDldacVrcyXbp8pBerf1LBfnQXmkPKmyLVGGLus8", SignatureMethod::HmacSha1)
        .token("862962650-rIcjsj0j9ZJ8khPVA8jZTtEJuq7YYDBDpx6fOAgb", "kbMQjdVldI6tFOST3SVjmyAtG1D0oCkCpL6vBv1FtA")
        .finish_for_twitter();
}
