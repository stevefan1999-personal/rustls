#![allow(clippy::duplicate_mod)]

use super::lib;
use crate::crypto;

pub(crate) static HMAC_SHA256: Hmac = Hmac(&lib::hmac::HMAC_SHA256);
pub(crate) static HMAC_SHA384: Hmac = Hmac(&lib::hmac::HMAC_SHA384);
#[cfg(all(test, feature = "tls12"))]
pub(crate) static HMAC_SHA512: Hmac = Hmac(&lib::hmac::HMAC_SHA512);

pub(crate) struct Hmac(&'static lib::hmac::Algorithm);

impl crypto::hmac::Hmac for Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(Key(lib::hmac::Key::new(*self.0, key)))
    }

    fn hash_output_len(&self) -> usize {
        self.0.digest_algorithm().output_len
    }
}

struct Key(lib::hmac::Key);

impl crypto::hmac::Key for Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let mut ctx = lib::hmac::Context::with_key(&self.0);
        ctx.update(first);
        for d in middle {
            ctx.update(d);
        }
        ctx.update(last);
        ctx.sign().into()
    }

    fn tag_len(&self) -> usize {
        self.0
            .algorithm()
            .digest_algorithm()
            .output_len
    }
}

impl From<lib::hmac::Tag> for crypto::hmac::Tag {
    fn from(val: lib::hmac::Tag) -> Self {
        Self::new(val.as_ref())
    }
}
