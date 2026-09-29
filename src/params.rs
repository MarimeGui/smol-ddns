use std::{collections::HashMap, net::IpAddr};

use thiserror::Error;

use crate::{
    config::{ConfigFile, TSIGParams},
    update::{ZoneType, group_zones},
};

pub struct Parameters {
    pub server: IpAddr,
    pub zones: HashMap<String, HashMap<String, Vec<ZoneType>>>,
    pub ttl: u32,
    pub tsig_params: Option<TSIGParams>,
}

impl Parameters {
    pub fn from_config(config: ConfigFile) -> Result<Self, ParametersError> {
        let server = config.dns_server.ok_or(ParametersError::NoSuitableServer)?;
        let zones = group_zones(&config);
        let ttl = config.ttl;
        let tsig_params = config.tsig_params;

        Ok(Self {
            server,
            zones,
            ttl,
            tsig_params,
        })
    }
}

#[derive(Debug, Error)]
pub enum ParametersError {
    #[error("no suitable DNS server was found")]
    NoSuitableServer,
}
