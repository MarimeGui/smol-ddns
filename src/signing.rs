use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::dns_protocol::add_name;

type HmacSha256 = Hmac<Sha256>;

pub const FUDGE: u16 = 300; // seconds

// RFC8945
pub fn sign_hmac_sha256(message: &mut Vec<u8>, key_name: &str, key_secret: &[u8], message_id: u16) {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut mac = HmacSha256::new_from_slice(key_secret).unwrap();

    mac.update(message); // Pass whole message

    // Extra data to append at the end to get a valid mac
    let mut extra_tsig_vars = Vec::new();
    add_name(&mut extra_tsig_vars, key_name); // Key name
    extra_tsig_vars.extend(&[0, 0xFF]); // Class ANY
    extra_tsig_vars.extend(&[0, 0, 0, 0]); // Time to Live
    add_name(&mut extra_tsig_vars, "hmac-sha256"); // Algorithm
    extra_tsig_vars.extend(&current_time.to_be_bytes()[2..8]); // Time signed
    extra_tsig_vars.extend(&FUDGE.to_be_bytes()); // Fudge
    extra_tsig_vars.extend(&[0, 0]); // Error
    extra_tsig_vars.extend(&[0, 0]); // Other Len
    mac.update(&extra_tsig_vars); // Add extra data

    let mac = mac.finalize().into_bytes();

    // ---- Modify message to include new record
    message[11] += 1; // Add 1 to additional records
    add_name(message, key_name); // Name
    message.extend(&[0, 0xFA]); // Type TSIG
    message.extend(&[0, 0xFF]); // Class ANY
    message.extend(&[0, 0, 0, 0]); // Time to Live
    message.extend(&[0, 0x3D]); // Data length
    add_name(message, "hmac-sha256"); // Algorithm
    message.extend(&current_time.to_be_bytes()[2..8]); // Time signed, according to RFC: "an unsigned 48-bit integer containing the time the message was signed as seconds since 00:00 on 1970-01-01 UTC, ignoring leap seconds"
    message.extend(&FUDGE.to_be_bytes()); // Fudge, "an unsigned 16-bit integer specifying the allowed time difference in seconds permitted in the Time Signed field."
    message.extend(&[0, 32]); // MAC Size
    message.extend(&mac); // MAC itself
    message.extend(&message_id.to_be_bytes()); // Original ID, u16
    message.extend(&[0, 0]); // Error
    message.extend(&[0, 0]); // Other Len
}
