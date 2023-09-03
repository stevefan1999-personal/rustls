use p256::ecdsa::signature::RandomizedSigner;
use p256::ecdsa::signature::SignatureEncoding;
use p256::pkcs8::DecodePrivateKey;
use rustls::crypto::CryptoProvider;
use rustls::server::{Acceptor, ClientHello, ResolvesServerCert};
use rustls::sign::SigningKey;
use rustls::{sign, PrivateKey, ServerConfig, SignatureAlgorithm, SignatureScheme};
use rustls_provider_example::Provider;
use std::io::Write;
use std::sync::Arc;

struct TestResolvesServerCert(Arc<sign::CertifiedKey>);

impl TestResolvesServerCert {
    pub fn new(cert_chain: Vec<rustls::Certificate>, key_der: rustls::PrivateKey) -> Self {
        Self(Arc::new(sign::CertifiedKey::new(
            cert_chain,
            Arc::new(
                EcdsaSigningKey::new(&key_der, SignatureScheme::ECDSA_NISTP256_SHA256).unwrap(),
            ),
        )))
    }
}

impl ResolvesServerCert for TestResolvesServerCert {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

struct EcdsaSigningKey {
    key: Arc<p256::ecdsa::SigningKey>,
    scheme: SignatureScheme,
}

impl EcdsaSigningKey {
    fn new(der: &PrivateKey, scheme: SignatureScheme) -> Result<Self, ()> {
        p256::ecdsa::SigningKey::from_pkcs8_der(&der.0)
            .map_err(|_| ())
            .map(|kp| Self {
                key: Arc::new(kp),
                scheme,
            })
    }
}

impl SigningKey for EcdsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn rustls::sign::Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(EcdsaSigner {
                key: Arc::clone(&self.key),
                scheme: self.scheme,
            }))
        } else {
            None
        }
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

struct EcdsaSigner {
    key: Arc<p256::ecdsa::SigningKey>,
    scheme: SignatureScheme,
}

impl rustls::sign::Signer for EcdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.key
            .try_sign_with_rng(&mut rand_core::OsRng, message)
            .map_err(|_| rustls::Error::General("signing failed".into()))
            .map(|sig: p256::ecdsa::Signature| sig.to_der().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

struct TestPki {
    server_cert_der: Vec<u8>,
    server_key_der: Vec<u8>,
}

impl TestPki {
    fn new() -> Self {
        let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        let mut ca_params = rcgen::CertificateParams::new(Vec::new());
        ca_params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, "Rustls Server Acceptor");
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Example CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        ca_params.alg = alg;
        let ca_cert = rcgen::Certificate::from_params(ca_params).unwrap();

        // Create a server end entity cert issued by the CA.
        let mut server_ee_params = rcgen::CertificateParams::new(vec!["localhost".to_string()]);
        server_ee_params.is_ca = rcgen::IsCa::NoCa;
        server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        server_ee_params.alg = alg;
        let server_cert = rcgen::Certificate::from_params(server_ee_params).unwrap();
        let server_cert_der = server_cert
            .serialize_der_with_signer(&ca_cert)
            .unwrap();
        let server_key_der = server_cert.serialize_private_key_der();

        Self {
            server_cert_der,
            server_key_der,
        }
    }

    fn server_config<C: CryptoProvider>(&self) -> Arc<ServerConfig<C>> {
        let mut server_config: ServerConfig<C> = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(TestResolvesServerCert::new(
                vec![rustls::Certificate(self.server_cert_der.clone())],
                PrivateKey(self.server_key_der.clone()),
            )));

        server_config.key_log = Arc::new(rustls::KeyLogFile::new());

        Arc::new(server_config)
    }
}

fn main() {
    env_logger::init();

    let pki = TestPki::new();
    let server_config = pki.server_config::<Provider>();

    let listener = std::net::TcpListener::bind(format!("0.0.0.0:{}", 4443)).unwrap();
    'accept: for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();

        let accepted = loop {
            if let Ok(_) = acceptor.read_tls(&mut stream) {
                if let Ok(Some(accepted)) = acceptor.accept() {
                    break accepted;
                }
            }

            eprintln!("unexpected connection");
            continue 'accept;
        };

        match accepted.into_connection(server_config.clone()) {
            Ok(mut conn) => {
                let msg = concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Connection: Closed\r\n",
                    "Content-Type: text/html\r\n",
                    "\r\n",
                    "<h1>Hello World!</h1>\r\n"
                )
                .as_bytes();

                let _ = conn.writer().write(msg);
                let _ = conn.write_tls(&mut stream);
                _ = conn.complete_io(&mut stream);

                conn.send_close_notify();
                let _ = conn.write_tls(&mut stream);
                _ = conn.complete_io(&mut stream);
            }
            Err(e) => {
                eprintln!("{}", e);
            }
        }
    }
}
