//! This module provides functionality for handling RSA private keys.
//!
//! It includes methods for loading, saving, generating, and managing RSA keys
//! using the OpenSSL library.

use std::fs::File;
use std::io::Write;
use std::ops::Deref;

use anyhow::{bail, Context, Result};
use log::info;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::symm::Cipher;

use crate::console::ask_passphrase;

use super::console::confirm;

/// Represents an RSA private key.
pub struct Key(PKey<Private>);

impl Deref for Key {
    type Target = PKey<Private>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Key {
    /// Loads an RSA private key from a PEM file.
    pub fn load(path: &str) -> Result<Self> {
        info!("Reading key file: {}", path);
        let pem_data =
            std::fs::read(path).with_context(|| format!("Error loading key file {}", path))?;
        let rsa = Rsa::private_key_from_pem(&pem_data)?;

        info!("Key file read OK");
        Ok(Self(PKey::from_rsa(rsa)?))
    }

    /// Saves the RSA private key to a PEM file.
    pub fn save(&mut self, path: &str) -> Result<()> {
        let mut passphrase = None;
        loop {
            let passphrase1 = ask_passphrase("Enter passphrase: ")?;
            if passphrase1.is_empty() {
                break;
            }
            let passphrase2 = ask_passphrase("Confirm passphrase: ")?;

            if passphrase1 == passphrase2 {
                passphrase = Some(passphrase1);
                break;
            }
            println!("Entered passphrases do not match.");
        }

        let mut private_key_file = File::create(path)?;
        let pem_data = if let Some(passphrase) = passphrase {
            info!("Writing encrypted key file: {}", path);
            self.0
                .private_key_to_pem_pkcs8_passphrase(Cipher::aes_256_cbc(), passphrase.as_bytes())?
        } else {
            info!("Writing key file: {}", path);
            self.0.private_key_to_pem_pkcs8()?
        };
        private_key_file.write_all(&pem_data)?;

        Ok(())
    }

    /// Generates a new RSA private key.
    pub fn generate() -> Result<Self> {
        info!("Generating a new RSA key");
        let rsa = Rsa::generate(2048)?;
        Ok(Self(PKey::from_rsa(rsa)?))
    }

    /// Loads an existing RSA private key or generates a new one if it doesn't exist.
    pub fn load_or_generate(path: &str) -> Result<Self> {
        if let Ok(key) = Self::load(path) {
            info!("Key {} loaded OK", path);
            return Ok(key);
        }

        info!("Key {} does not exist", path);
        if !confirm(&format!("Generate key {}?", path)) {
            bail!("Canceled by user");
        }

        let mut key = Self::generate()?;
        key.save(path)?;
        Ok(key)
    }
}
