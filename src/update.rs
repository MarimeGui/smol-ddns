use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, UdpSocket},
};

use anyhow::Result;

use crate::{
    config::ConfigFile,
    dns_protocol::{
        Query, Update,
        UpdateInner::{self, DeleteAllA, DeleteAllAAAA},
    },
    params::Parameters,
    signing::sign_hmac_sha256,
};

pub fn make_and_send_updates(params: &Parameters, ips: &HashMap<IpAddr, u32>) -> Result<()> {
    let categories = categorize_ips(ips.iter().map(|e| *e.0));

    // Generate a query for each zone
    let queries = make_queries(&params.zones, &categories, params.ttl);

    for query in queries {
        // Make into bytes
        let mut out_bytes = query.to_bytes();

        // Sign with TSIG if necessary
        if let Some(tsig_params) = &params.tsig_params {
            let key = tsig_params.get_key()?;
            sign_hmac_sha256(
                &mut out_bytes,
                &tsig_params.key_name,
                &key,
                query.transaction_id,
            );
        }

        // Send update
        let socket = UdpSocket::bind(match params.server {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "::0:0",
        })?;
        socket.send_to(&out_bytes, (params.server, 53))?;
    }

    Ok(())
}

#[derive(Debug, Default)]
struct CategorizedIPs {
    link_local: Vec<Ipv6Addr>,
    unique_local: Vec<Ipv6Addr>,
    globally_unique: Vec<Ipv6Addr>,
    legacy: Vec<Ipv4Addr>,
}

fn categorize_ips(ips: impl Iterator<Item = IpAddr>) -> CategorizedIPs {
    let mut categories = CategorizedIPs::default();

    for ip in ips {
        let ipv6 = match ip {
            IpAddr::V4(ipv4_addr) => {
                categories.legacy.push(ipv4_addr);
                continue;
            }
            IpAddr::V6(ipv6_addr) => ipv6_addr,
        };

        if ipv6.is_unique_local() {
            categories.unique_local.push(ipv6);
        } else if ipv6.is_unicast_link_local() {
            categories.link_local.push(ipv6)
        } else if !ipv6.is_unspecified() {
            // Technically not correct, but should be fine
            categories.globally_unique.push(ipv6)
        }
    }

    categories
}

#[derive(Debug)]
pub enum ZoneType {
    LinkLocal,
    UniqueLocal,
    GloballyUnique,
    Legacy,
}

pub fn group_zones(config: &ConfigFile) -> HashMap<String, HashMap<String, Vec<ZoneType>>> {
    let mut res: HashMap<String, HashMap<String, Vec<ZoneType>>> = HashMap::new();

    if let Some((host, zone)) = &config.lla_fqdn {
        res.entry(zone.clone())
            .or_default()
            .entry(host.clone())
            .or_default()
            .push(ZoneType::LinkLocal);
    }

    if let Some((host, zone)) = &config.ula_fqdn {
        res.entry(zone.clone())
            .or_default()
            .entry(host.clone())
            .or_default()
            .push(ZoneType::UniqueLocal);
    }

    if let Some((host, zone)) = &config.gua_fqdn {
        res.entry(zone.clone())
            .or_default()
            .entry(host.clone())
            .or_default()
            .push(ZoneType::GloballyUnique);
    }

    if let Some((host, zone)) = &config.ipv4_fqdn {
        res.entry(zone.clone())
            .or_default()
            .entry(host.clone())
            .or_default()
            .push(ZoneType::Legacy);
    }

    res
}

fn make_queries(
    zones: &HashMap<String, HashMap<String, Vec<ZoneType>>>,
    categorized_ips: &CategorizedIPs,
    ttl: u32,
) -> Vec<Query> {
    let mut queries = Vec::new();

    // For each zone
    for (zone, entries) in zones {
        let mut updates = Vec::new();

        // For each hostname
        for (hostname, zone_types) in entries {
            let name = format!("{}.{}", hostname, zone);

            // First, delete all A and AAAA records
            updates.push(Update {
                name: name.clone(),
                data: DeleteAllA,
            });
            updates.push(Update {
                name: name.clone(),
                data: DeleteAllAAAA,
            });

            for zone_type in zone_types {
                let relevant_ips: Vec<UpdateInner> = match zone_type {
                    ZoneType::LinkLocal => categorized_ips
                        .link_local
                        .iter()
                        .map(|ip| UpdateInner::NewAAAA((*ip, ttl)))
                        .collect(),
                    ZoneType::UniqueLocal => categorized_ips
                        .unique_local
                        .iter()
                        .map(|ip| UpdateInner::NewAAAA((*ip, ttl)))
                        .collect(),
                    ZoneType::GloballyUnique => categorized_ips
                        .globally_unique
                        .iter()
                        .map(|ip| UpdateInner::NewAAAA((*ip, ttl)))
                        .collect(),
                    ZoneType::Legacy => categorized_ips
                        .legacy
                        .iter()
                        .map(|ip| UpdateInner::NewA((*ip, ttl)))
                        .collect(),
                };

                for data in relevant_ips {
                    updates.push(Update {
                        name: name.clone(),
                        data,
                    });
                }
            }
        }

        queries.push(Query {
            transaction_id: rand::random(),
            zone: zone.clone(),
            updates,
        });
    }

    queries
}
