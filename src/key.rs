//! This module provides functionality for handling RSA private keys.
//!
//! It includes methods for loading, saving, generating, and managing RSA keys
//! using the OpenSSL library.

use std::fs::File;
use std::io::Write;
use std::ops::Deref;

use anyhow::{bail, Context, Result};
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;

use super::console::confirm;

/// Represents an RSA private key.
pub struct Key(PKey<Private>);

impl TryFrom<Rsa<Private>> for Key {
    type Error = openssl::error::ErrorStack;

    fn try_from(value: Rsa<Private>) -> Result<Self, Self::Error> {
        Ok(Self(PKey::from_rsa(value)?))
    }
}

impl Deref for Key {
    type Target = PKey<Private>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Key {
    /// Loads an RSA private key from a PEM file.
    pub fn load(path: &str) -> Result<Self> {
        let pem_data =
            std::fs::read(path).with_context(|| format!("Error loading key file {}", path))?;
        let rsa = Rsa::private_key_from_pem(&pem_data)?;
        Ok(rsa.try_into()?)
    }

    /// Saves the RSA private key to a PEM file.
    pub fn save(&self, path: &str) -> Result<()> {
        let mut private_key_file = File::create(path)?;
        let pem_data = self.0.private_key_to_pem_pkcs8()?;
        private_key_file.write_all(&pem_data)?;
        Ok(())
    }

    /// Generates a new RSA private key.
    pub fn generate() -> Result<Self> {
        let rsa = Rsa::generate(2048)?;
        Ok(rsa.try_into()?)
    }

    /// Loads an existing RSA private key or generates a new one if it doesn't exist.
    pub fn load_or_generate(path: &str) -> Result<Self> {
        let path = path.as_ref();
        if let Ok(key) = Self::load(path) {
            return Ok(key);
        }

        if !confirm(&format!("Generate key {}?", path)) {
            bail!("Canceled by user");
        }

        Self::generate()
    }
}
