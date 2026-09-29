use std::{
    collections::HashMap,
    net::{SocketAddr, ToSocketAddrs},
};

use thiserror::Error;

use crate::{
    config::{ConfigFile, TSIGParams},
    update::{ZoneType, group_zones},
};

pub struct Parameters {
    pub server_socket_addr: SocketAddr,
    pub zones: HashMap<String, HashMap<String, Vec<ZoneType>>>,
    pub gua_as_ula: bool,
    pub ttl: u32,
    pub tsig_params: Option<TSIGParams>,
}

impl Parameters {
    pub fn from_config(config: ConfigFile) -> Result<Self, ParametersError> {
        let zones = group_zones(&config);
        let gua_as_ula = config.gua_as_ula;
        let ttl = config.ttl;
        let tsig_params = config.tsig_params;

        // Resolve DNS server IP
        let provided_server = config.dns_server.ok_or(ParametersError::NoSuitableServer)?;
        let server_socket_addrs = (provided_server.as_str(), 53)
            .to_socket_addrs()
            .map_err(|_| ParametersError::InvalidServer)?
            .next()
            .ok_or(ParametersError::NoSuitableServer)?;

        Ok(Self {
            server_socket_addr: server_socket_addrs,
            zones,
            gua_as_ula,
            ttl,
            tsig_params,
        })
    }
}

#[derive(Debug, Error)]
pub enum ParametersError {
    #[error("no suitable DNS server was found")]
    NoSuitableServer,
    #[error("could not resolve server to any address")]
    InvalidServer,
}
