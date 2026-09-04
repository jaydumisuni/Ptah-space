use crate::{CredentialFingerprint, LinkError};
use rustls::{
    ClientConfig, ProtocolVersion, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
    server::WebPkiClientVerifier,
};
use std::{fmt, sync::Arc};
use tokio::net::TcpStream;
use tokio_rustls::{
    TlsAcceptor, TlsConnector, client::TlsStream as ClientTlsStream,
    server::TlsStream as ServerTlsStream,
};

/// In-memory TLS identity material for one E01 process.
///
/// Private key bytes are retained only in the Rustls PKI private-key wrapper and
/// are never exposed by this type's [`Debug`](fmt::Debug) implementation.
pub struct TlsIdentity {
    certificates: Vec<CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
}

impl TlsIdentity {
    /// Build an identity from an ordered DER certificate chain and DER private key.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::TlsConfiguration`] when the certificate chain is
    /// empty or the private key DER cannot be identified as a supported key.
    pub fn from_der(
        certificate_chain_der: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
    ) -> Result<Self, LinkError> {
        if certificate_chain_der.is_empty() {
            return Err(LinkError::TlsConfiguration(String::from(
                "TLS identity requires at least one certificate",
            )));
        }
        if certificate_chain_der.iter().any(Vec::is_empty) {
            return Err(LinkError::TlsConfiguration(String::from(
                "TLS identity contains an empty certificate",
            )));
        }
        let private_key = PrivateKeyDer::try_from(private_key_der).map_err(|_| {
            LinkError::TlsConfiguration(String::from("invalid TLS private-key DER"))
        })?;
        let certificates = certificate_chain_der
            .into_iter()
            .map(CertificateDer::from)
            .collect();
        Ok(Self {
            certificates,
            private_key,
        })
    }

    /// Build an identity from PEM-encoded certificates and one PEM private key.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::TlsConfiguration`] when PEM decoding fails, the
    /// certificate chain is empty, or no private key is present.
    pub fn from_pem(certificate_pem: &[u8], private_key_pem: &[u8]) -> Result<Self, LinkError> {
        let certificates = CertificateDer::pem_slice_iter(certificate_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| LinkError::TlsConfiguration(error.to_string()))?;
        if certificates.is_empty() {
            return Err(LinkError::TlsConfiguration(String::from(
                "TLS identity PEM contains no certificates",
            )));
        }
        let private_key = PrivateKeyDer::from_pem_slice(private_key_pem)
            .map_err(|error| LinkError::TlsConfiguration(error.to_string()))?;
        Ok(Self {
            certificates,
            private_key,
        })
    }
}

impl fmt::Debug for TlsIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsIdentity")
            .field("certificate_count", &self.certificates.len())
            .field("private_key", &"REDACTED")
            .finish()
    }
}

/// E01 trust-anchor set for authenticating the opposite TLS peer.
#[derive(Clone, Debug)]
pub struct TlsTrustRoots {
    store: RootCertStore,
}

impl TlsTrustRoots {
    /// Build trust roots from DER-encoded CA certificates.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::TlsConfiguration`] when no trust roots are supplied
    /// or any supplied root cannot be accepted by Rustls.
    pub fn from_der(root_certificates_der: Vec<Vec<u8>>) -> Result<Self, LinkError> {
        if root_certificates_der.is_empty() {
            return Err(LinkError::TlsConfiguration(String::from(
                "TLS trust roots cannot be empty",
            )));
        }
        let mut store = RootCertStore::empty();
        for root in root_certificates_der {
            store
                .add(CertificateDer::from(root))
                .map_err(|error| LinkError::TlsConfiguration(error.to_string()))?;
        }
        Ok(Self { store })
    }

    /// Build trust roots from PEM-encoded CA certificates.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::TlsConfiguration`] when PEM decoding fails or no
    /// certificate is present.
    pub fn from_pem(root_certificates_pem: &[u8]) -> Result<Self, LinkError> {
        let roots = CertificateDer::pem_slice_iter(root_certificates_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| LinkError::TlsConfiguration(error.to_string()))?;
        if roots.is_empty() {
            return Err(LinkError::TlsConfiguration(String::from(
                "TLS trust-root PEM contains no certificates",
            )));
        }
        let mut store = RootCertStore::empty();
        for root in roots {
            store
                .add(root)
                .map_err(|error| LinkError::TlsConfiguration(error.to_string()))?;
        }
        Ok(Self { store })
    }
}

/// TLS 1.3-only server configuration requiring a trusted client certificate.
#[derive(Clone)]
pub struct TlsServerConfig {
    inner: Arc<ServerConfig>,
}

impl TlsServerConfig {
    /// Construct the E01 mutual-authentication server configuration.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::TlsConfiguration`] when client verification or the
    /// server certificate/key pair cannot be configured.
    pub fn new(identity: TlsIdentity, trust_roots: TlsTrustRoots) -> Result<Self, LinkError> {
        let client_verifier = WebPkiClientVerifier::builder(Arc::new(trust_roots.store))
            .build()
            .map_err(|error| LinkError::TlsConfiguration(error.to_string()))?;
        let inner = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(identity.certificates, identity.private_key)
            .map_err(|error| LinkError::TlsConfiguration(error.to_string()))?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }
}

impl fmt::Debug for TlsServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsServerConfig")
            .field("protocol", &"TLSv1_3")
            .field("private_key", &"REDACTED")
            .finish()
    }
}

/// TLS 1.3-only client configuration presenting a trusted client certificate.
#[derive(Clone)]
pub struct TlsClientConfig {
    inner: Arc<ClientConfig>,
}

impl TlsClientConfig {
    /// Construct the E01 mutual-authentication client configuration.
    ///
    /// # Errors
    ///
    /// Returns [`LinkError::TlsConfiguration`] when the client certificate/key
    /// pair cannot be configured.
    pub fn new(identity: TlsIdentity, trust_roots: TlsTrustRoots) -> Result<Self, LinkError> {
        let inner = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(trust_roots.store)
            .with_client_auth_cert(identity.certificates, identity.private_key)
            .map_err(|error| LinkError::TlsConfiguration(error.to_string()))?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }
}

impl fmt::Debug for TlsClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsClientConfig")
            .field("protocol", &"TLSv1_3")
            .field("private_key", &"REDACTED")
            .finish()
    }
}

/// Authenticated TLS stream accepted by the control side of the E01 link.
pub struct AuthenticatedServerStream {
    stream: ServerTlsStream<TcpStream>,
    peer_fingerprint: CredentialFingerprint,
}

impl AuthenticatedServerStream {
    /// Return the authenticated client's end-entity certificate fingerprint.
    #[must_use]
    pub const fn peer_fingerprint(&self) -> CredentialFingerprint {
        self.peer_fingerprint
    }

    /// Return whether the negotiated protocol is exactly TLS 1.3.
    #[must_use]
    pub fn is_tls13(&self) -> bool {
        matches!(
            self.stream.get_ref().1.protocol_version(),
            Some(ProtocolVersion::TLSv1_3)
        )
    }

    /// Borrow the encrypted async stream for transport-neutral E01 framing.
    #[must_use]
    pub const fn stream_mut(&mut self) -> &mut ServerTlsStream<TcpStream> {
        &mut self.stream
    }
}

/// Authenticated TLS stream initiated by a Node.
pub struct AuthenticatedClientStream {
    stream: ClientTlsStream<TcpStream>,
    peer_fingerprint: CredentialFingerprint,
}

impl AuthenticatedClientStream {
    /// Return the authenticated server end-entity certificate fingerprint.
    #[must_use]
    pub const fn peer_fingerprint(&self) -> CredentialFingerprint {
        self.peer_fingerprint
    }

    /// Return whether the negotiated protocol is exactly TLS 1.3.
    #[must_use]
    pub fn is_tls13(&self) -> bool {
        matches!(
            self.stream.get_ref().1.protocol_version(),
            Some(ProtocolVersion::TLSv1_3)
        )
    }

    /// Borrow the encrypted async stream for transport-neutral E01 framing.
    #[must_use]
    pub const fn stream_mut(&mut self) -> &mut ClientTlsStream<TcpStream> {
        &mut self.stream
    }
}

/// Perform a TLS 1.3 mutual-authentication server handshake.
///
/// # Errors
///
/// Returns [`LinkError::TlsHandshake`] when the TLS handshake fails, or
/// [`LinkError::TlsPeerCertificateMissing`] if no authenticated client
/// end-entity certificate is available after the handshake.
pub async fn accept_tls(
    tcp: TcpStream,
    config: &TlsServerConfig,
) -> Result<AuthenticatedServerStream, LinkError> {
    let stream = TlsAcceptor::from(config.inner.clone())
        .accept(tcp)
        .await
        .map_err(|error| LinkError::TlsHandshake(error.to_string()))?;
    let peer_certificate = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or(LinkError::TlsPeerCertificateMissing)?;
    let peer_fingerprint = CredentialFingerprint::from_der(peer_certificate.as_ref());
    Ok(AuthenticatedServerStream {
        stream,
        peer_fingerprint,
    })
}

/// Perform a TLS 1.3 mutual-authentication client handshake.
///
/// # Errors
///
/// Returns [`LinkError::InvalidServerName`] for an invalid DNS name,
/// [`LinkError::TlsHandshake`] when the TLS handshake fails, or
/// [`LinkError::TlsPeerCertificateMissing`] if no authenticated server
/// end-entity certificate is available after the handshake.
pub async fn connect_tls(
    tcp: TcpStream,
    server_name: &str,
    config: &TlsClientConfig,
) -> Result<AuthenticatedClientStream, LinkError> {
    let server_name =
        ServerName::try_from(server_name.to_owned()).map_err(|_| LinkError::InvalidServerName)?;
    let stream = TlsConnector::from(config.inner.clone())
        .connect(server_name, tcp)
        .await
        .map_err(|error| LinkError::TlsHandshake(error.to_string()))?;
    let peer_certificate = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .ok_or(LinkError::TlsPeerCertificateMissing)?;
    let peer_fingerprint = CredentialFingerprint::from_der(peer_certificate.as_ref());
    Ok(AuthenticatedClientStream {
        stream,
        peer_fingerprint,
    })
}
