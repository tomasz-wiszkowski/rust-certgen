#![feature(fs_try_exists)]

mod cert;
mod console;
mod key;

use std::collections::HashMap;
use std::io::Write;
use std::ops::Deref;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use colored::*;
use log::info;

use openssl::nid::Nid;
use openssl::x509::X509Name;
use serde::Deserialize;

use cert::Certificate;
use cert::CertificateBuilder;
use console::confirm;
use key::Key;

const CONFIG_FILE_NAME: &str = "certgen.toml";

#[derive(Deserialize, Debug)]
struct Config {
    network: NetworkCfg,
    sites: HashMap<String, SiteCfg>,
}

#[derive(Deserialize, Debug)]
struct NetworkCfg {
    name: String,
    email: String,
    country: Option<String>,
    province: Option<String>,

    #[serde(default = "default_root_ca_name")]
    root_ca_name: String,
    #[serde(default = "default_root_ca_validity_days")]
    root_ca_validity_days: u32,
}

#[derive(Deserialize, Debug)]
struct SiteCfg {
    name: String,
    #[serde(default = "default_crt_validity_days")]
    crt_validity_days: u32,
    alt_names: Vec<String>,
}

fn default_root_ca_name() -> String {
    "root_ca".into()
}

fn default_crt_validity_days() -> u32 {
    365 * 2
}

fn default_root_ca_validity_days() -> u32 {
    365 * 100
}

struct Network(NetworkCfg);
struct Site(String, SiteCfg);

impl Deref for Network {
    type Target = NetworkCfg;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for Site {
    type Target = SiteCfg;

    fn deref(&self) -> &Self::Target {
        &self.1
    }
}

impl Network {
    fn build_subject_name(&self, site: Option<&Site>) -> Result<X509Name> {
        let mut name_builder = openssl::x509::X509NameBuilder::new()?;
        name_builder
            .append_entry_by_nid(Nid::COMMONNAME, site.map(|s| &s.0).unwrap_or(&self.name))?;
        name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, &self.name)?;
        name_builder.append_entry_by_nid(
            Nid::ORGANIZATIONALUNITNAME,
            site.map(|s| &s.name).unwrap_or(&self.name),
        )?;
        name_builder.append_entry_by_nid(Nid::PKCS9_EMAILADDRESS, &self.email)?;

        if let Some(country) = self.country.as_ref() {
            name_builder.append_entry_by_nid(Nid::COUNTRYNAME, country)?;
        }
        if let Some(province) = self.province.as_ref() {
            name_builder.append_entry_by_nid(Nid::STATEORPROVINCENAME, province)?;
        }

        Ok(name_builder.build())
    }
}

fn load_or_generate_ca_cert(net: &Network) -> Result<Certificate> {
    if let Ok(crt) = Certificate::load(&net.root_ca_name) {
        info!("Certificate Authority read OK");
        return Ok(crt);
    }

    info!("Certificate auhtority does not exist");
    if !confirm(&format!(
        "Certificate {} does not exist. Generate a new one?",
        net.root_ca_name
    )) {
        bail!("Aborted by user");
    }

    let key = Key::load_or_generate(&format!("{}.key", net.root_ca_name))?;
    let mut crt = CertificateBuilder::new(key)?;
    let subject = net.build_subject_name(None)?;

    crt.set_issuer_name(&subject)?;
    crt.set_subject_name(&subject)?;
    crt.set_certificate_authority()?;
    crt.set_validity_period(net.root_ca_validity_days)?;
    crt.sign_self()?;

    let x509 = crt.build();
    x509.save(&net.root_ca_name)?;
    return Ok(x509);
}

fn main() -> Result<()> {
    env_logger::Builder::from_default_env()
        .format_target(false)
        .format(|buf, record| {
            let style = buf.default_level_style(record.level()).dimmed();
            writeln!(
                buf,
                "{style}[{:1.1}] {}{style:#}",
                record.level(),
                record.args()
            )
        })
        .init();

    info!("Reading configuration file: {}", CONFIG_FILE_NAME);
    let toml_str = std::fs::read_to_string(CONFIG_FILE_NAME).context(format!(
        "Unable to read configuration file {}",
        CONFIG_FILE_NAME
    ))?;
    let config: Config = toml::from_str(&toml_str)?;

    let network = Network(config.network);
    let ca_cert = load_or_generate_ca_cert(&network)?;

    for (site_name, site_cfg) in config.sites {
        let site = Site(site_name, site_cfg);

        let site_key = Key::load_or_generate(&format!("{}.key", &site.0))?;
        let site_crt = CertificateBuilder::new(site_key)?;
        let mut site_crt = site_crt.set_server_auth()?;

        // Set issuer and subject name
        let subject = network.build_subject_name(Some(&site))?;
        site_crt.set_subject_name(&subject)?;
        site_crt.set_issuer_name(ca_cert.subject_name())?;
        site_crt.set_validity_period(site.crt_validity_days)?;
        site_crt.set_subject_alt_names(&site.alt_names)?;

        ca_cert.sign(&mut site_crt)?;

        let x509 = site_crt.build();
        x509.save(&site.0)?;
    }

    Ok(())
}
