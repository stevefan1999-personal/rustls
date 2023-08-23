#![allow(clippy::duplicate_mod)]

use super::lib;
use crate::crypto;
use crate::msgs::enums::HashAlgorithm;

pub(crate) static SHA256: Hash = Hash(&lib::digest::SHA256, HashAlgorithm::SHA256);
pub(crate) static SHA384: Hash = Hash(&lib::digest::SHA384, HashAlgorithm::SHA384);

pub(crate) struct Hash(&'static lib::digest::Algorithm, HashAlgorithm);

impl crypto::hash::Hash for Hash {
    fn start(&self) -> Box<dyn crypto::hash::Context> {
        Box::new(Context(lib::digest::Context::new(self.0)))
    }

    fn hash(&self, bytes: &[u8]) -> crypto::hash::Output {
        let mut ctx = lib::digest::Context::new(self.0);
        ctx.update(bytes);
        ctx.finish().into()
    }

    fn output_len(&self) -> usize {
        self.0.output_len
    }

    fn algorithm(&self) -> HashAlgorithm {
        self.1
    }
}

struct Context(lib::digest::Context);

impl crypto::hash::Context for Context {
    fn fork_finish(&self) -> crypto::hash::Output {
        self.0.clone().finish().into()
    }

    fn fork(&self) -> Box<dyn crypto::hash::Context> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> crypto::hash::Output {
        self.0.finish().into()
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

impl From<lib::digest::Digest> for crypto::hash::Output {
    fn from(val: lib::digest::Digest) -> Self {
        Self::new(val.as_ref())
    }
}
