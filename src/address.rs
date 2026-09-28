//! Bech32m address encode/decode (xch1 / txch1).

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, Hrp};
use chia_protocol::Bytes32;

use crate::error::{Error, Result};
use crate::network::Network;

pub fn decode_address(addr: &str) -> Result<(String, Bytes32)> {
    let addr = addr.trim();
    let checked = CheckedHrpstring::new::<Bech32m>(addr)
        .map_err(|e| Error::msg(format!("invalid address: {e}")))?;
    let bytes: Vec<u8> = checked.byte_iter().collect();
    if bytes.len() != 32 {
        return Err(Error::msg("address payload is not a 32-byte puzzle hash"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok((checked.hrp().to_lowercase(), Bytes32::new(arr)))
}

pub fn encode_address(puzzle_hash: Bytes32, hrp: &str) -> Result<String> {
    let hrp = Hrp::parse(hrp).map_err(|e| Error::msg(format!("invalid address prefix: {e}")))?;
    bech32::encode::<Bech32m>(hrp, &puzzle_hash.to_bytes())
        .map_err(|e| Error::msg(format!("encode address: {e}")))
}

pub fn network_from_address_prefix(hrp: &str) -> Option<Network> {
    match hrp {
        "xch" => Some(Network::Mainnet),
        "txch" => Some(Network::Testnet11),
        _ => None,
    }
}

const RECEIVE_ADDRESS_HELP: &str =
    "expected vault Receive address (xch1… for mainnet, or txch1… for testnet11)";

/// Validate a vault Receive address (`xch1…` / `txch1…`). Hex launcher ids are rejected.
pub fn validate_receive_address(input: &str) -> Result<()> {
    let input = input.trim();
    let lower = input.to_ascii_lowercase();
    if !lower.starts_with("xch1") && !lower.starts_with("txch1") {
        return Err(Error::msg(RECEIVE_ADDRESS_HELP));
    }
    decode_address(input)?;
    Ok(())
}

/// Parse and return a trimmed Receive address. Hex launcher ids are rejected.
pub fn parse_receive_address(input: &str) -> Result<String> {
    let input = input.trim();
    validate_receive_address(input)?;
    Ok(input.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_xch() {
        let ph = Bytes32::new([0xab; 32]);
        let addr = encode_address(ph, "xch").unwrap();
        assert!(addr.starts_with("xch1"));
        let (hrp, decoded) = decode_address(&addr).unwrap();
        assert_eq!(hrp, "xch");
        assert_eq!(decoded, ph);
    }

    #[test]
    fn receive_address_rejects_launcher_id() {
        let id = format!("0x{}", hex::encode([0x22; 32]));
        assert!(parse_receive_address(&id).is_err());
    }

    #[test]
    fn receive_address_accepts_xch_and_txch() {
        let ph = Bytes32::new([0xcd; 32]);
        let mainnet = encode_address(ph, "xch").unwrap();
        let testnet = encode_address(ph, "txch").unwrap();
        assert_eq!(parse_receive_address(&mainnet).unwrap(), mainnet);
        assert_eq!(parse_receive_address(&testnet).unwrap(), testnet);
    }
}
