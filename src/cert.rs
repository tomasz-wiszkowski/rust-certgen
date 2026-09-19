//! This module provides functionality for building and managing X.509 certificates.
//!
//! It includes structures for certificate building, site-specific certificate building,
//! and certificate management. The module uses OpenSSL for cryptographic operations.

use anyhow::{bail, Context, Result};
use log::info;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    hash::MessageDigest,
    x509::{X509Builder, X509Ref, X509},
};
use std::cmp::Ordering;
use std::net::IpAddr;
use std::ops::{Deref, DerefMut};

use crate::key::Key;

/// Returns a certificate's serial number.
pub fn serial_number(cert: &X509Ref) -> Result<u32> {
    let serial = cert.serial_number().to_bn()?.to_dec_str()?.parse()?;
    Ok(serial)
}

/// Returns true if the certificate expires within `days` days from now.
pub fn expires_within(cert: &X509Ref, days: u32) -> Result<bool> {
    let threshold = Asn1Time::days_from_now(days)?;
    Ok(cert.not_after().compare(threshold.as_ref())? != Ordering::Greater)
}

/// A builder for X.509 certificates.
pub struct CertificateBuilder(X509Builder, Key);

impl DerefMut for CertificateBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for CertificateBuilder {
    type Target = X509Builder;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl CertificateBuilder {
    /// Creates a new CertificateBuilder with the given key.
    pub fn new(key: Key) -> Result<Self> {
        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        builder.set_pubkey(&key)?;

        Ok(Self(builder, key))
    }

    /// Sets the certificate's serial number.
    pub fn set_serial_number(&mut self, serial: u32) -> Result<()> {
        let asn1_serial = BigNum::from_u32(serial)?.to_asn1_integer()?;
        self.0.set_serial_number(&asn1_serial).map_err(Into::into)
    }

    /// Sets the validity period for the certificate.
    pub fn set_validity_period(&mut self, days: u32) -> Result<()> {
        self.0
            .set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        self.0
            .set_not_after(Asn1Time::days_from_now(days)?.as_ref())?;
        Ok(())
    }

    /// Signs the certificate with its own key.
    pub fn sign_self(&mut self) -> Result<()> {
        self.0
            .sign(&self.1, MessageDigest::sha256())
            .map_err(Into::into)
    }

    /// Builds the certificate.
    pub fn build(self) -> Certificate {
        info!("Generating certificate");
        Certificate(self.0.build(), self.1)
    }

    /// Sets the certificate as a Certificate Authority, restricted to signing leaf
    /// certificates only (no intermediate CAs below it).
    pub fn set_certificate_authority(&mut self) -> Result<()> {
        self.0
            .append_extension(
                openssl::x509::extension::BasicConstraints::new()
                    .critical()
                    .ca()
                    .pathlen(0)
                    .build()?,
            )
            .map_err(Into::into)
    }

    /// Sets the Key Usage extension for a Certificate Authority: signing certificates and CRLs.
    pub fn set_ca_key_usage(&mut self) -> Result<()> {
        self.0
            .append_extension(
                openssl::x509::extension::KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()?,
            )
            .map_err(Into::into)
    }

    /// Sets the Subject Key Identifier extension: a hash of this certificate's own public key.
    pub fn set_subject_key_identifier(&mut self) -> Result<()> {
        let ski = openssl::x509::extension::SubjectKeyIdentifier::new()
            .build(&self.x509v3_context(None, None))?;
        self.append_extension(ski).map_err(Into::into)
    }

    /// Sets the Authority Key Identifier extension, identifying the key that signs this
    /// certificate. Pass `None` for a self-signed certificate, or `Some(issuer)` when signed
    /// by another CA.
    pub fn set_authority_key_identifier(&mut self, issuer: Option<&X509Ref>) -> Result<()> {
        let aki = openssl::x509::extension::AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&self.x509v3_context(issuer, None))?;
        self.append_extension(aki).map_err(Into::into)
    }

    /// Configures the certificate for server authentication and returns a SiteCertificateBuilder.
    pub fn set_server_auth(mut self) -> Result<SiteCertificateBuilder> {
        self.0.append_extension(
            openssl::x509::extension::ExtendedKeyUsage::new()
                .server_auth()
                .build()?,
        )?;
        Ok(SiteCertificateBuilder(self))
    }
}

/// A builder for site-specific certificates.
pub struct SiteCertificateBuilder(CertificateBuilder);

impl DerefMut for SiteCertificateBuilder {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for SiteCertificateBuilder {
    type Target = CertificateBuilder;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SiteCertificateBuilder {
    /// Sets the Key Usage extension for a TLS server certificate: signing the handshake and,
    /// for RSA keys, decrypting an encrypted key sent by the client.
    pub fn set_server_key_usage(&mut self) -> Result<()> {
        self.append_extension(
            openssl::x509::extension::KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .build()?,
        )
        .map_err(Into::into)
    }

    /// Sets the Subject Alternative Names for the certificate.
    pub fn set_subject_alt_names(&mut self, alt_names: &[String]) -> Result<()> {
        let mut san = openssl::x509::extension::SubjectAlternativeName::new();
        for name in alt_names {
            if name.parse::<IpAddr>().is_ok() {
                san.ip(name);
            } else if name.contains(':') {
                // Not a valid IP (that branch already handles bare IPv6 literals), and a DNS
                // name can never contain a colon, so this is almost certainly a host:port or
                // ip:port typo. TLS certificates cannot be scoped to a port -- reject it instead
                // of silently emitting a DNS SAN entry that will never match anything.
                bail!(
                    "Invalid alt_names entry {:?}: contains ':' but is not a valid IP address. \
                     A certificate cannot be scoped to a port; remove it and list just the host \
                     or IP.",
                    name
                );
            } else {
                san.dns(name);
            }
        }
        let extension = san.build(&self.x509v3_context(None, None))?;
        self.append_extension(extension).map_err(Into::into)
    }

    /// Builds the site-specific certificate.
    pub fn build(self) -> Certificate {
        self.0.build()
    }
}

/// Represents an X.509 certificate.
pub struct Certificate(X509, Key);

impl Deref for Certificate {
    type Target = X509;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Certificate {
    /// Loads just the certificate portion (not the key) from file, e.g. to inspect
    /// its serial number or expiry without needing (and possibly having to decrypt) the key.
    pub fn load_cert_only(name: &str) -> Result<X509> {
        let crt_path = format!("{}.crt", name);
        info!("Reading certificate file: {}", crt_path);
        let crt = X509::from_pem(
            &std::fs::read(&crt_path)
                .context(format!("Error loading certificate file {}", &crt_path))?,
        )?;
        Ok(crt)
    }

    /// Loads a certificate and its corresponding key from files.
    pub fn load(name: &str) -> Result<Self> {
        let crt_path = format!("{}.crt", name);
        let key_path = format!("{}.key", name);

        let key = Key::load(&key_path)?;

        info!("Reading certificate file: {}", crt_path);
        let crt = X509::from_pem(
            &std::fs::read(&crt_path)
                .context(format!("Error loading certificate file {}", &crt_path))?,
        )?;
        info!("Certificate read OK");
        Ok(Self(crt, key))
    }

    /// Saves a certificate and its corresponding key to files.
    pub fn save(&self, name: &str) -> Result<()> {
        info!("Writing certificate {}.crt", name);
        Ok(std::fs::write(&format!("{}.crt", &name), self.0.to_pem()?)?)
    }

    /// Signs another certificate using this certificate's key.
    pub fn sign(&self, builder: &mut CertificateBuilder) -> Result<()> {
        info!("Signing certificate");
        builder
            .sign(&self.1, MessageDigest::sha256())
            .map_err(Into::into)
    }
}
