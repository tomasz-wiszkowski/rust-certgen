//! This module provides functionality for building and managing X.509 certificates.
//!
//! It includes structures for certificate building, site-specific certificate building,
//! and certificate management. The module uses OpenSSL for cryptographic operations.

use anyhow::{Context, Result};
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    x509::{X509Builder, X509},
};
use std::ops::{Deref, DerefMut};

use crate::key::Key;

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
        Certificate(self.0.build(), self.1)
    }

    /// Sets the certificate as a Certificate Authority.
    pub fn set_certificate_authority(&mut self) -> Result<()> {
        self.0
            .append_extension(
                openssl::x509::extension::BasicConstraints::new()
                    .ca()
                    .build()?,
            )
            .map_err(Into::into)
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
    /// Sets the Subject Alternative Names for the certificate.
    pub fn set_subject_alt_names(&mut self, alt_names: &[String]) -> Result<()> {
        let mut san = openssl::x509::extension::SubjectAlternativeName::new();
        alt_names.iter().for_each(|name| {
            san.dns(name);
        });
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
    /// Loads a certificate and its corresponding key from files.
    pub fn load(name: &str) -> Result<Self> {
        let crt_path = format!("{}.crt", name);
        let key_path = format!("{}.key", name);

        let crt = X509::from_pem(
            &std::fs::read(&crt_path)
                .context(format!("Error loading certificate file {}", &crt_path))?,
        )?;

        let key = Key::load(&key_path)?;

        Ok(Self(crt, key))
    }

    /// Saves a certificate and its corresponding key to files.
    pub fn save(&self, name: &str) -> Result<()> {
        self.1.save(&format!("{}.key", name))?;
        Ok(std::fs::write(&format!("{}.crt", &name), self.0.to_pem()?)?)
    }

    /// Signs another certificate using this certificate's key.
    pub fn sign(&self, builder: &mut CertificateBuilder) -> Result<()> {
        builder
            .sign(&self.1, MessageDigest::sha256())
            .map_err(Into::into)
    }
}
