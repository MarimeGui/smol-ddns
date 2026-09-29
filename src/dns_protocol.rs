use std::net::{Ipv4Addr, Ipv6Addr};

// I am not validating anything
pub fn add_name(vec: &mut Vec<u8>, name: &str) {
    for part in name.split('.') {
        if part.is_empty() {
            continue;
        }

        vec.extend(&[part.len() as u8]);
        vec.extend(part.as_bytes());
    }
    vec.extend(&[0]);
}

#[derive(Debug)]
pub struct Update {
    /// Name of the record to update
    pub name: String,
    pub data: UpdateInner,
}

/// This implementation isn't really record types like in the actual packet
/// it represents more like things you can do
#[derive(Debug, Clone)]
pub enum UpdateInner {
    NewA((Ipv4Addr, u32)),
    NewAAAA((Ipv6Addr, u32)),
    // TODO: Doesn't work currently, apparently needs class NONE
    // DeleteA(Ipv4Addr),
    // DeleteAAAA(Ipv6Addr),
    DeleteAllA,
    DeleteAllAAAA,
    #[allow(dead_code)] // Not using it actually
    DeleteAll,
}

impl UpdateInner {
    const fn type_field_value(&self) -> u16 {
        match self {
            UpdateInner::DeleteAll => 255,
            UpdateInner::NewA(_) | UpdateInner::DeleteAllA => 1,
            UpdateInner::NewAAAA(_) | UpdateInner::DeleteAllAAAA => 28,
        }
    }

    const fn class_field_value(&self) -> u16 {
        match self {
            UpdateInner::DeleteAllA | UpdateInner::DeleteAllAAAA | UpdateInner::DeleteAll => 255, // Class ANY
            _ => 1, // Class Internet
        }
    }

    fn time_to_live(&self) -> u32 {
        match self {
            UpdateInner::NewA((_, ttl)) | UpdateInner::NewAAAA((_, ttl)) => *ttl,
            _ => 0,
        }
    }

    const fn data_length(&self) -> u16 {
        match self {
            UpdateInner::NewA(_) => 4,
            UpdateInner::NewAAAA(_) => 16,
            UpdateInner::DeleteAllA | UpdateInner::DeleteAllAAAA | UpdateInner::DeleteAll => 0,
        }
    }
}

#[derive(Debug)]
pub struct Query {
    pub transaction_id: u16,
    pub zone: String,
    pub updates: Vec<Update>,
}

impl Query {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // ---- Header
        bytes.extend(&self.transaction_id.to_be_bytes()); // Transaction ID
        bytes.extend(&[0x28, 0]); // Flags field, just setting opcode to Dynamic updates
        bytes.extend(&1u16.to_be_bytes()); // Zone count
        bytes.extend(&0u16.to_be_bytes()); // Prerequisites, none... Is this ever used ?
        bytes.extend(&(self.updates.len() as u16).to_be_bytes()); // Update count
        bytes.extend(&0u16.to_be_bytes()); // Additional RRs count, for now 0. If signing with TSIG, the count needs to be updated later.

        // ---- Zone
        add_name(&mut bytes, &self.zone);
        bytes.extend(&[0, 6]); // Type SOA
        bytes.extend(&[0, 1]); // Class Internet

        // ---- Updates
        for update in &self.updates {
            add_name(&mut bytes, &update.name); // Name
            bytes.extend(&update.data.type_field_value().to_be_bytes()); // Type
            bytes.extend(&update.data.class_field_value().to_be_bytes()); // Class
            bytes.extend(&update.data.time_to_live().to_be_bytes()); // TTL
            bytes.extend(&update.data.data_length().to_be_bytes()); // Data Length

            // IP Address
            match update.data {
                UpdateInner::NewA((ipv4_addr, _)) => {
                    bytes.extend(&ipv4_addr.octets());
                }
                UpdateInner::NewAAAA((ipv6_addr, _)) => {
                    bytes.extend(&ipv6_addr.octets());
                }
                UpdateInner::DeleteAllA | UpdateInner::DeleteAllAAAA | UpdateInner::DeleteAll => {}
            }
        }

        bytes
    }
}

pub fn check_response(query: &Query, response: &[u8]) -> ResponseResult {
    let mut pos = 0;

    if query.transaction_id != u16::from_be_bytes([response[0], response[1]]) {
        return ResponseResult::TransactionIdDifferent;
    }
    pos += 2;

    // Check response in flags
    let flags = u16::from_be_bytes([response[pos], response[pos + 1]]);
    pos += 2;
    if (flags & (1u16 << 15)) == 0 {
        return ResponseResult::NotResponse;
    }
    let response_code = ServerResponseCode::from_code(flags & 0b1111).unwrap();
    if response_code != ServerResponseCode::NoError {
        return ResponseResult::Error(response_code);
    }

    // Zone count
    pos += 2;

    // Prerequisites
    pos += 2;

    // Update count
    pos += 2;

    // Additional RRs
    pos += 2;

    // Skip zone
    loop {
        // Read length
        let len = response[pos];
        pos += 1;
        if len == 0 {
            // Text over
            // pos += 1;
            break;
        }
        // Skip actual text
        pos += len as usize;
    }

    // Some other stuff afterwards
    // println!("Left: {:x?}", &response[pos..]);

    ResponseResult::NoError
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResponseResult {
    NoError,
    TransactionIdDifferent,
    NotResponse,
    Error(ServerResponseCode),
}

#[derive(Debug, PartialEq, Eq)]
pub enum ServerResponseCode {
    NoError,
    FormError,
    ServFail,
    NxDomain,
    NotImp,
    Refused,
    YxDomain,
    YxRRSet,
    NxRRSet,
    NotAuth,
    NotZone,
}

impl ServerResponseCode {
    pub const fn from_code(code: u16) -> Option<Self> {
        Some(match code {
            0 => Self::NoError,
            1 => Self::FormError,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            6 => Self::YxDomain,
            7 => Self::YxRRSet,
            8 => Self::NxRRSet,
            9 => Self::NotAuth,
            10 => Self::NotZone,
            _ => return None,
        })
    }
}
