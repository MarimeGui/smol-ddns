use std::{collections::HashMap, net::IpAddr};

use anyhow::Result;
use futures_util::{StreamExt, TryStreamExt};
use rtnetlink::{
    MulticastGroup, new_connection, new_multicast_connection,
    packet_core::{NetlinkMessage, NetlinkPayload},
    packet_route::{
        RouteNetlinkMessage,
        address::{AddressAttribute, AddressMessage, AddressScope},
    },
};

use crate::{params::Parameters, update::make_and_send_updates};

pub async fn monitor_changes(params: &Parameters, ips: &mut HashMap<IpAddr, u32>) -> Result<()> {
    // Open a connection to Netlink
    let (conn, _handle, mut messages) =
        new_multicast_connection(&[MulticastGroup::Ipv4Ifaddr, MulticastGroup::Ipv6Ifaddr])?;
    tokio::spawn(conn);

    while let Some((message, _)) = messages.next().await {
        let (operation, msg) = if let Some(s) = open_netlink_message(message) {
            s
        } else {
            continue;
        };

        let (address, index) = if let Some(s) = process_address_message(&msg) {
            s
        } else {
            continue;
        };

        let mut new_all_addresses = ips.clone();
        match operation {
            IpUpdateType::New => new_all_addresses.insert(address, index),
            IpUpdateType::Del => new_all_addresses.remove(&address),
        };

        if new_all_addresses == *ips {
            // I observed that sometimes, NewAddress events are fired even though the addresses stay the same.
            // To avoid sending updates for no reason, stop here if nothing was updated.
            continue;
        }

        *ips = new_all_addresses;

        println!("Detected changes, new IPs are: {:?}", ips.keys());

        // Re-send updated list of IPs to DNS
        make_and_send_updates(params, ips)?;
    }

    Ok(())
}

pub enum IpUpdateType {
    New,
    Del,
}

pub fn open_netlink_message(
    message: NetlinkMessage<RouteNetlinkMessage>,
) -> Option<(IpUpdateType, AddressMessage)> {
    let inner = if let NetlinkPayload::InnerMessage(m) = message.payload {
        m
    } else {
        // Other payloads are not interesting here
        return None;
    };

    let operation;
    let msg;
    match inner {
        RouteNetlinkMessage::NewAddress(a) => {
            operation = IpUpdateType::New;
            msg = a;
        }
        RouteNetlinkMessage::DelAddress(a) => {
            operation = IpUpdateType::Del;
            msg = a
        }

        // Ignore all other message types
        _ => return None,
    }

    Some((operation, msg))
}

// /// Returns all links on the system
// pub async fn find_all_interfaces() -> Result<HashMap<u32, String>> {
//     let mut res = HashMap::new();
//     let (connection, handle, _) = new_connection()?;
//     tokio::spawn(connection);

//     let mut links = handle.link().get().execute();

//     while let Some(msg) = links.try_next().await? {
//         let index = msg.header.index;
//         let mut name = None;
//         for attribute in &msg.attributes {
//             if let LinkAttribute::IfName(n) = attribute {
//                 name = Some(n.clone())
//             }
//         }
//         let name = if let Some(n) = name {
//             n
//         } else {
//             // Ignore interfaces without names
//             continue;
//         };

//         res.insert(index, name);
//     }

//     Ok(res)
// }

pub async fn find_all_addresses() -> Result<HashMap<IpAddr, u32>> {
    let mut res = HashMap::new();

    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    let mut addresses = handle.address().get().execute();

    while let Some(msg) = addresses.try_next().await? {
        if let Some((address, index)) = process_address_message(&msg) {
            res.insert(address, index);
        }
    }

    Ok(res)
}

pub fn process_address_message(msg: &AddressMessage) -> Option<(IpAddr, u32)> {
    let index = msg.header.index;

    // Skip all loopback addresses
    if msg.header.scope == AddressScope::Host {
        return None;
    }

    // Extract address
    let address = *extract_address(msg)?;

    Some((address, index))
}

fn extract_address(msg: &AddressMessage) -> Option<&IpAddr> {
    let mut address = None;
    for attribute in &msg.attributes {
        if let AddressAttribute::Address(a) = attribute {
            address = Some(a)
        }
    }
    address
}
