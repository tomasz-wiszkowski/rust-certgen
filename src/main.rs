#![feature(fs_try_exists)]

use anyhow::bail;
use anyhow::Result;

use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::{hash::MessageDigest, pkey::Private};

use openssl::x509::X509;
use std::fs::File;
use std::{
    collections::HashMap,
    io::{self, Write},
};

use serde::Deserialize;

#[derive(Deserialize, Debug)]
struct SiteCert {
    name: Option<String>,
    max_age_days: Option<u32>,
    alt_names: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct Network {
    name: String,
    email: String,
    country: Option<String>,
    province: Option<String>,

    default_max_age_days: u32,

    root_ca_key: String,
    root_ca_crt: String,
}

#[derive(Deserialize, Debug)]
struct Config {
    network: Network,
    site_certs: HashMap<String, SiteCert>,
}

fn ask<T: AsRef<str>>(prompt: T) -> bool {
    let mut ans = String::new();
    print!("{} (y/N): ", prompt.as_ref());
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut ans).unwrap();

    ans.to_lowercase().starts_with("y")
}

fn read_key<T: AsRef<str>>(path: T) -> Result<PKey<Private>> {
    if !std::fs::try_exists(path.as_ref())? {
        if !ask(format!(
            "Key {} does not exist. Create new one?",
            path.as_ref()
        )) {
            bail!("Aborted by user");
        }

        let rsa = Rsa::generate(2048)?;
        let mut private_key_file = File::create(path.as_ref())?;
        private_key_file.write_all(&rsa.private_key_to_pem()?)?;
    }

    let ca_key = Rsa::private_key_from_pem(&std::fs::read(path.as_ref())?)?;
    Ok(PKey::from_rsa(ca_key)?)
}

fn read_root_crt(net: &Network) -> Result<X509> {
    if !std::fs::try_exists(&net.root_ca_crt)? {
        if !ask(format!(
            "Certificate {} does not exist. Create new one?",
            net.root_ca_crt
        )) {
            bail!("Aborted by user");
        }

        let key = read_key(&net.root_ca_key)?;

        let mut x509_builder = X509::builder()?;
        x509_builder.set_version(2)?;
        x509_builder.set_pubkey(&key)?;

        let mut name_builder = openssl::x509::X509NameBuilder::new()?;
        name_builder.append_entry_by_nid(Nid::COMMONNAME, &net.name)?;
        name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, &net.name)?;
        name_builder.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, &net.name)?;
        name_builder.append_entry_by_nid(Nid::PKCS9_EMAILADDRESS, &net.email)?;

        if let Some(country) = net.country.as_ref() {
            name_builder.append_entry_by_nid(Nid::COUNTRYNAME, country)?;
        }
        if let Some(province) = net.province.as_ref() {
            name_builder.append_entry_by_nid(Nid::STATEORPROVINCENAME, province)?;
        }

        let name = name_builder.build();
        x509_builder.set_subject_name(&name)?;
        // Self-signed.
        x509_builder.set_issuer_name(&name)?;

        x509_builder.append_extension(
            openssl::x509::extension::ExtendedKeyUsage::new()
                .server_auth()
                .build()?,
        )?;

        x509_builder.append_extension(
            openssl::x509::extension::BasicConstraints::new()
                .ca()
                .build()?,
        )?;

        // Set validity period to 100 years.
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(365 * 100)?;
        x509_builder.set_not_before(&not_before)?;
        x509_builder.set_not_after(&not_after)?;

        // Self-sign the certificate
        x509_builder.sign(&key, MessageDigest::sha256())?;

        let x509 = x509_builder.build();
        std::fs::write(&net.root_ca_crt, x509.to_pem()?)?;
    }

    Ok(X509::from_pem(&std::fs::read(&net.root_ca_crt)?)?)
}

fn main() -> Result<()> {
    let toml_str = std::fs::read_to_string("certgen.toml")?;
    let config: Config = toml::from_str(&toml_str)?;

    let ca_pkey = read_key(&config.network.root_ca_key)?;
    let ca_cert = read_root_crt(&config.network)?;
    let ca_subject_name = ca_cert.subject_name();

    for (site_name, site_cfg) in &config.site_certs {
        let site_pkey = read_key(&format!("{}.key", site_name))?;

        let mut x509_builder = X509::builder()?;
        x509_builder.set_version(2)?;
        x509_builder.set_pubkey(&site_pkey)?;

        // Set issuer and subject name
        x509_builder.set_issuer_name(ca_subject_name)?;

        let mut name_builder = openssl::x509::X509NameBuilder::new()?;
        name_builder.append_entry_by_nid(Nid::COMMONNAME, &site_name)?;
        name_builder.append_entry_by_nid(Nid::PKCS9_EMAILADDRESS, &config.network.email)?;
        name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, &config.network.name)?;
        name_builder.append_entry_by_nid(
            Nid::ORGANIZATIONALUNITNAME,
            site_cfg.name.as_ref().unwrap_or(&site_name),
        )?;
        if let Some(country) = config.network.country.as_ref() {
            name_builder.append_entry_by_nid(Nid::COUNTRYNAME, country)?;
        }
        if let Some(province) = config.network.province.as_ref() {
            name_builder.append_entry_by_nid(Nid::STATEORPROVINCENAME, province)?;
        }

        let name = name_builder.build();
        x509_builder.set_subject_name(&name)?;

        x509_builder.append_extension(
            openssl::x509::extension::ExtendedKeyUsage::new()
                .server_auth()
                .build()?,
        )?;

        let mut san = openssl::x509::extension::SubjectAlternativeName::new();
        site_cfg.alt_names.iter().for_each(|name| {
            san.dns(name.as_ref());
        });
        x509_builder.append_extension(san.build(&x509_builder.x509v3_context(None, None))?)?;

        // Set validity period
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(
            site_cfg
                .max_age_days
                .unwrap_or(config.network.default_max_age_days),
        )?;
        x509_builder.set_not_before(&not_before)?;
        x509_builder.set_not_after(&not_after)?;

        // Sign the certificate
        x509_builder.sign(&ca_pkey, MessageDigest::sha256())?;

        let x509 = x509_builder.build();
        std::fs::write(&format!("{}.crt", site_name), x509.to_pem()?)?;
    }

    Ok(())
}
