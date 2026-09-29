use std::{fs::File, io::BufReader, path::Path};

use anyhow::Result;
use base64::prelude::{BASE64_STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ConfigFile {
    /// Address of the server to send updates to. Can be an address or a hostname. If None, will try to figure it out from system.
    pub dns_server: Option<String>,
    /// If enabled, all updates will be signed using TSIG.
    pub tsig_params: Option<TSIGParams>,

    /// If there is no Unique Local Address available, use the Globally Unique Address to populate ULA records.
    pub gua_as_ula: bool,

    /// Time-to-live of updated records
    pub ttl: u32,

    /// FQDN to update for Link-local IPv6 addresses.
    pub lla_fqdn: Option<(String, String)>,
    /// FQDN to update for Unique local IPv6 addresses.
    pub ula_fqdn: Option<(String, String)>,
    /// FQDN to update for Globally unique IPv6 addresses.
    pub gua_fqdn: Option<(String, String)>,
    /// FQDN to update for IPv4 addresses.
    pub ipv4_fqdn: Option<(String, String)>,

    /// Generate a reverse PTR record for Link-local IPv6 addresses ?
    pub lla_ptr: bool,
    /// Generate a reverse PTR record for Unique local IPv6 addresses ?
    pub ula_ptr: bool,
    /// Generate a reverse PTR record for Globally unique IPv6 addresses ?
    pub gua_ptr: bool,
    /// Generate a reverse PTR record for IPv4 addresses ?
    pub ipv4_ptr: bool,
}

impl ConfigFile {
    pub fn from_file(config_path: &Path) -> Result<Self> {
        Ok(serde_yaml::from_reader(BufReader::new(File::open(
            config_path,
        )?))?)
    }
}

#[derive(Serialize, Deserialize)]
pub struct TSIGParams {
    /// Name of this key
    pub key_name: String,
    /// HMAC SHA256 Base64-encoded secret
    pub key_secret: String,
}

impl TSIGParams {
    pub fn get_key(&self) -> Result<Vec<u8>, base64::DecodeError> {
        BASE64_STANDARD.decode(&self.key_secret)
    }
}

pub fn example_config() -> ConfigFile {
    ConfigFile {
        dns_server: Some("dns.test".to_string()),
        tsig_params: Some(TSIGParams {
            key_name: "my_super_key".to_string(),
            // This key is just an example, don't worry I'm not using it :)
            key_secret: "NzrFJTklHQltxfu/WhfvVZENwds24dJL3r1ET/394UE=".to_string(),
        }),
        gua_as_ula: true,
        ttl: 3600,
        lla_fqdn: Some((
            "my_machine".to_string(),
            "ll.infra.internal.test".to_string(),
        )),
        lla_ptr: false,
        ula_fqdn: None,
        ula_ptr: false,
        gua_fqdn: Some((
            "my_machine".to_string(),
            "g.infra.internal.test".to_string(),
        )),
        gua_ptr: true,
        ipv4_fqdn: Some((
            "my_machine".to_string(),
            "l.infra.internal.test".to_string(),
        )),
        ipv4_ptr: true,
    }
}

pub fn example_yaml_config() -> String {
    serde_yaml::to_string(&example_config()).unwrap()
}
