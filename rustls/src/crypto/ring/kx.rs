use super::lib::agreement::{
    self, agree_ephemeral, EphemeralPrivateKey, PublicKey, UnparsedPublicKey,
};
use super::lib::rand::SystemRandom;
use crate::crypto::{self, KeyExchangeError, SupportedGroup};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::enums::NamedGroup;

use core::fmt;

/// An in-progress key exchange.  This has the algorithm,
/// our private key, and our public key.
#[derive(Debug)]
pub struct KeyExchange {
    group: &'static SupportedKxGroup,
    priv_key: EphemeralPrivateKey,
    pub_key: PublicKey,
}

impl crypto::KeyExchange for KeyExchange {
    type SupportedGroup = SupportedKxGroup;

    fn start(
        name: NamedGroup,
        supported: &[&'static SupportedKxGroup],
    ) -> Result<Self, KeyExchangeError> {
        let group = match supported
            .iter()
            .find(|group| group.name == name)
        {
            Some(group) => group,
            None => return Err(KeyExchangeError::UnsupportedGroup),
        };

        let rng = SystemRandom::new();
        let priv_key = match EphemeralPrivateKey::generate(group.agreement_algorithm, &rng) {
            Ok(priv_key) => priv_key,
            Err(_) => return Err(KeyExchangeError::GetRandomFailed),
        };

        let pub_key = match priv_key.compute_public_key() {
            Ok(pub_key) => pub_key,
            Err(_) => return Err(KeyExchangeError::GetRandomFailed),
        };

        Ok(Self {
            group,
            priv_key,
            pub_key,
        })
    }

    /// Completes the key exchange, given the peer's public key.
    ///
    /// The shared secret is passed into the closure passed down in `f`, and the result of calling
    /// `f` is returned to the caller.
    fn complete<T>(self, peer: &[u8], f: impl FnOnce(&[u8]) -> Result<T, ()>) -> Result<T, Error> {
        let peer_key = UnparsedPublicKey::new(self.group.agreement_algorithm, peer);
        agree_ephemeral(self.priv_key, &peer_key, (), f)
            .map_err(|()| PeerMisbehaved::InvalidKeyShare.into())
    }

    /// Return the group being used.
    fn group(&self) -> NamedGroup {
        self.group.name
    }

    /// Return the public key being used.
    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }

    /// Return all supported key exchange groups.
    fn all_kx_groups() -> &'static [&'static Self::SupportedGroup] {
        &ALL_KX_GROUPS
    }
}

/// A key-exchange group supported by *ring*.
///
/// All possible instances of this class are provided by the library in
/// the `ALL_KX_GROUPS` array.
pub struct SupportedKxGroup {
    /// The IANA "TLS Supported Groups" name of the group
    pub name: NamedGroup,

    /// The corresponding ring agreement::Algorithm
    agreement_algorithm: &'static agreement::Algorithm,
}

impl SupportedGroup for SupportedKxGroup {
    fn name(&self) -> NamedGroup {
        self.name
    }
}

impl fmt::Debug for SupportedKxGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name.fmt(f)
    }
}

/// Ephemeral ECDH on curve25519 (see RFC7748)
pub static X25519: SupportedKxGroup = SupportedKxGroup {
    name: NamedGroup::X25519,
    agreement_algorithm: &agreement::X25519,
};

/// Ephemeral ECDH on secp256r1 (aka NIST-P256)
pub static SECP256R1: SupportedKxGroup = SupportedKxGroup {
    name: NamedGroup::secp256r1,
    agreement_algorithm: &agreement::ECDH_P256,
};

/// Ephemeral ECDH on secp384r1 (aka NIST-P384)
pub static SECP384R1: SupportedKxGroup = SupportedKxGroup {
    name: NamedGroup::secp384r1,
    agreement_algorithm: &agreement::ECDH_P384,
};

/// A list of all the key exchange groups supported by rustls.
pub static ALL_KX_GROUPS: [&SupportedKxGroup; 3] = [&X25519, &SECP256R1, &SECP384R1];
