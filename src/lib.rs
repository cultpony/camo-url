use hmac::{Hmac, Mac, NewMac};
use std::{str::FromStr, time::Duration};
use url::Url;

#[derive(Clone, securefmt::Debug)]
pub struct CamoConfig {
    #[sensitive]
    key: Vec<u8>,
    host: url::Url,
    lifetime: Option<std::time::Duration>,
}

type HmacSha1 = Hmac<crypto_hashes::sha1::Sha1>;
type HmacBlake2b = Hmac<crypto_hashes::blake2::Blake2b>;

impl CamoConfig {
    pub fn new<S1: Into<String>, S2: Into<String>>(
        key: S1,
        host: S2,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let key: Vec<u8> = hex::decode(key.into())?;
        let host = Url::from_str(&host.into())?;
        Ok(Self::new_from(key, host))
    }

    pub fn new_with_lifetime<S1: Into<String>, S2: Into<String>>(
        key: S1,
        host: S2,
        lifetime: Duration,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let key: Vec<u8> = hex::decode(key.into())?;
        let host = Url::from_str(&host.into())?;
        Ok(Self::new_from_with_lifetime(key, host, lifetime))
    }

    pub fn new_from(key: Vec<u8>, host: Url) -> Self {
        Self {
            key,
            host,
            lifetime: None,
        }
    }

    pub fn new_from_with_lifetime(key: Vec<u8>, host: Url, lifetime: Duration) -> Self {
        Self {
            key,
            host,
            lifetime: Some(lifetime),
        }
    }

    pub fn get_camo_url(&self, url: &Url) -> Result<Url, Box<dyn std::error::Error>> {
        let urlstr = url.to_string();
        let urldigest = self.digest(&urlstr);
        let urldigest = hex::encode(urldigest);
        let mut base = self.host.clone();
        base.query_pairs_mut().append_pair("url", &urlstr);
        base.path_segments_mut()
            .map_err(|_| "could not append digest")?
            .push(&urldigest);
        Ok(base)
    }

    pub fn get_camo_url_inline(&self, url: &Url) -> Result<Url, Box<dyn std::error::Error>> {
        let urlstr = url.to_string();
        let urldigest = self.digest(&urlstr);
        let urldigest = hex::encode(urldigest);
        let mut base = self.host.clone();
        base.path_segments_mut()
            .map_err(|_| "could not append digest")?
            .push(&urldigest)
            .push(&hex::encode(urlstr))
            .push("");
        Ok(base)
    }

    pub fn get_camo_v2_url(
        &self,
        url: &Url,
        base_time: std::time::SystemTime,
    ) -> Result<Url, Box<dyn std::error::Error>> {
        let urlstr = url.to_string();
        let urldigest = self.digest(&urlstr);
        let urldigest = hex::encode(urldigest);
        let mut base = self.host.clone();
        base.query_pairs_mut().append_pair("url", &urlstr);
        base.path_segments_mut()
            .map_err(|_| "could not append digest")?
            .push(&urldigest);
        let v2str = if let Some(lifetime) = self.lifetime {
            let expiry = (base_time + lifetime)
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time is bad or lifetime negative")
                .as_secs()
                .to_string();
            base.query_pairs_mut().append_pair("expires", &expiry);

            let urldigestv2 = self.v2digest(&(expiry + &urlstr));
            hex::encode(urldigestv2)
        } else {
            let urldigestv2 = self.v2digest(&urlstr);
            hex::encode(urldigestv2)
        };
        base.query_pairs_mut().append_pair("urlv2", &v2str);
        Ok(base)
    }

    fn digest(&self, urlstr: &str) -> Vec<u8> {
        let mut hasher: HmacSha1 =
            HmacSha1::new_varkey(&self.key).expect("could not take SHA1 key");
        hasher.update(urlstr.as_bytes());
        let result = hasher.finalize();
        result.into_bytes().as_slice().to_vec()
    }

    fn v2digest(&self, urlstr: &str) -> Vec<u8> {
        let mut hasher: HmacBlake2b =
            HmacBlake2b::new_varkey(&self.key).expect("could not take Blake2b key");
        hasher.update(urlstr.as_bytes());
        let result = hasher.finalize();
        result.into_bytes().as_slice().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn camo_inline() {
        let key = "somekeythatisuniqueandstufflikethat";
        let key = hex::encode(key);
        let host = "https://www.example.com";
        let camo = CamoConfig::new(key, host).expect("must work");
        let url = r#"http://40.media.tumblr.com/4574de09e1207dbb872f9c018adb57c8/tumblr_ngya1hYUBO1rq9ek2o1_1280.jpg"#;
        let url = Url::from_str(url).expect("test url doesn't parse");
        let d = camo.get_camo_url_inline(&url).expect("must work");
        let expected = r#"https://www.example.com/3608e93ba99430a7fb28344e910330004ad51b84/687474703a2f2f34302e6d656469612e74756d626c722e636f6d2f34353734646530396531323037646262383732663963303138616462353763382f74756d626c725f6e67796131685955424f31727139656b326f315f313238302e6a7067/"#;
        assert_eq!(expected, d.to_string());
    }

    #[test]
    fn camo_urlquery() {
        let key = "somekeythatisuniqueandstufflikethat";
        let key = hex::encode(key);
        let host = "https://www.example.com";
        let camo = CamoConfig::new(key, host).expect("must work");
        let url = r#"http://40.media.tumblr.com/4574de09e1207dbb872f9c018adb57c8/tumblr_ngya1hYUBO1rq9ek2o1_1280.jpg"#;
        let url = Url::from_str(url).expect("test url doesn't parse");
        let d = camo.get_camo_url(&url).expect("must work");
        let expected = r#"https://www.example.com/3608e93ba99430a7fb28344e910330004ad51b84?url=http%3A%2F%2F40.media.tumblr.com%2F4574de09e1207dbb872f9c018adb57c8%2Ftumblr_ngya1hYUBO1rq9ek2o1_1280.jpg"#;
        assert_eq!(expected, d.to_string());
    }

    #[test]
    fn camo_v2() {
        let key = "somekeythatisuniqueandstufflikethat";
        let key = hex::encode(key);
        let host = "https://www.example.com";
        let camo =
            CamoConfig::new_with_lifetime(key, host, Duration::from_secs(120)).expect("must work");
        let url = r#"http://40.media.tumblr.com/4574de09e1207dbb872f9c018adb57c8/tumblr_ngya1hYUBO1rq9ek2o1_1280.jpg"#;
        let url = Url::from_str(url).expect("test url doesn't parse");
        let time = std::time::UNIX_EPOCH;
        let d = camo.get_camo_v2_url(&url, time).expect("must work");
        let expected = r#"https://www.example.com/3608e93ba99430a7fb28344e910330004ad51b84?url=http%3A%2F%2F40.media.tumblr.com%2F4574de09e1207dbb872f9c018adb57c8%2Ftumblr_ngya1hYUBO1rq9ek2o1_1280.jpg&expires=120&urlv2=441dc4e4d2dc89f3c7731b0c8b72f6f5fcba196a0fab70eac20508151e402eb092a7a9cf9dd73e9636a7854fbbf0f6aa6cd32e1228d89bf8668f5715f9116eb7"#;
        assert_eq!(expected, d.to_string());
    }
}
