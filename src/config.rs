//! Cloud Wallet vault-config JSON (export/import format).

use std::fs;
use std::path::Path;

use chia_protocol::Bytes32;
use serde::{Deserialize, Serialize};

use crate::address::validate_receive_address;
use crate::error::{Error, Result};
use crate::keys::{KeyPair, parse_bls_public_key, parse_hex_bytes, public_key_to_hex};
use crate::vault::{CustodyPath, VaultKeys, VaultMemberKey};

/// Public-key / nested-vault members in Cloud Wallet config shape.
pub fn config_members_from_keys(
    keys: &[VaultMemberKey],
    vault_launcher_ids: &[Bytes32],
) -> Vec<VaultConfigMember> {
    let mut out = Vec::new();
    for key in keys {
        out.push(match key {
            VaultMemberKey::Bls(pk) => VaultConfigMember::PublicKey {
                public_key: public_key_to_hex(pk),
                curve: Curve::Bls12_381,
                key_type: None,
            },
            VaultMemberKey::K1(pk) => VaultConfigMember::PublicKey {
                public_key: format!("0x{}", hex::encode(pk.to_bytes())),
                curve: Curve::Secp256k1,
                key_type: Some(KeyType::App),
            },
            VaultMemberKey::R1(pk) => VaultConfigMember::PublicKey {
                public_key: format!("0x{}", hex::encode(pk.to_bytes())),
                curve: Curve::Secp256r1,
                key_type: Some(KeyType::App),
            },
            VaultMemberKey::Passkey(pk) => VaultConfigMember::PublicKey {
                public_key: format!("0x{}", hex::encode(pk.to_bytes())),
                curve: Curve::Webauthn,
                key_type: Some(KeyType::Passkey),
            },
        });
    }
    for launcher_id in vault_launcher_ids {
        out.push(VaultConfigMember::Vault {
            launcher_id: format!("0x{}", hex::encode(launcher_id)),
        });
    }
    out
}

/// Inverse of [`config_members_from_keys`]. Empty input is allowed (hash-only custody).
pub fn keys_from_config_members(
    members: &[VaultConfigMember],
) -> Result<(Vec<VaultMemberKey>, Vec<Bytes32>)> {
    let mut keys = Vec::new();
    let mut vault_launcher_ids = Vec::new();
    for member in members {
        match member {
            VaultConfigMember::PublicKey {
                public_key, curve, ..
            } => keys.push(member_key(*curve, public_key)?),
            VaultConfigMember::Vault { launcher_id } => {
                vault_launcher_ids.push(parse_bytes32(launcher_id)?);
            }
        }
    }
    Ok((keys, vault_launcher_ids))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Curve {
    Secp256k1,
    Secp256r1,
    Webauthn,
    Bls12_381,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyType {
    Passkey,
    App,
    AppSoftware,
    RecoveryPhrase,
    Vault,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum VaultConfigMember {
    #[serde(rename = "publicKey")]
    PublicKey {
        #[serde(rename = "publicKey")]
        public_key: String,
        curve: Curve,
        #[serde(rename = "keyType", default)]
        key_type: Option<KeyType>,
    },
    #[serde(rename = "vault")]
    Vault {
        #[serde(rename = "launcherId")]
        launcher_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultConfigSide {
    pub threshold: u32,
    #[serde(default)]
    pub members: Vec<VaultConfigMember>,
    /// MIPS custody-path hash. Required when `members` is empty (on-chain discovery).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultConfigRecovery {
    pub threshold: u32,
    pub clawback_timelock: u64,
    pub members: Vec<VaultConfigMember>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultConfig {
    pub launcher_id: String,
    pub custody: VaultConfigSide,
    pub recovery: VaultConfigRecovery,
    /// Receive address that selected the network. Not part of the on-chain layout.
    /// Written at Start so finish still works after a later lookup replaces the cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receive_address: Option<String>,
}

impl VaultConfig {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let text = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&text)?)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        fs::write(path, text)?;
        Ok(())
    }

    pub fn launcher_id_bytes(&self) -> Result<Bytes32> {
        parse_bytes32(&self.launcher_id)
    }

    /// Receive address written at Start. Finish and inspect use this instead of the lookup cache.
    pub fn recorded_receive_address(&self) -> Result<&str> {
        let address = self
            .receive_address
            .as_deref()
            .map(str::trim)
            .filter(|address| !address.is_empty())
            .ok_or_else(|| {
                Error::msg(
                    "vault config has no Receive address; run start so the file records xch1… or txch1…",
                )
            })?;
        validate_receive_address(address)?;
        Ok(address)
    }

    pub fn to_vault_keys(&self) -> Result<VaultKeys> {
        Ok(VaultKeys {
            custody: side_to_custody(&self.custody)?,
            recovery: recovery_to_signers(&self.recovery)?,
        })
    }

    /// Build a simple post-recovery config: 1-of-1 BLS custody + 1-of-1 BLS recovery.
    /// Does not include private mnemonics.
    pub fn from_bls_pair(
        launcher_id: Bytes32,
        custody: &KeyPair,
        recovery: &KeyPair,
        clawback_timelock: u64,
    ) -> Self {
        Self {
            launcher_id: format!("0x{}", hex::encode(launcher_id)),
            custody: VaultConfigSide {
                threshold: 1,
                members: vec![VaultConfigMember::PublicKey {
                    public_key: public_key_to_hex(&custody.public_key),
                    curve: Curve::Bls12_381,
                    key_type: Some(KeyType::RecoveryPhrase),
                }],
                hash: None,
            },
            recovery: VaultConfigRecovery {
                threshold: 1,
                clawback_timelock,
                members: vec![VaultConfigMember::PublicKey {
                    public_key: public_key_to_hex(&recovery.public_key),
                    curve: Curve::Bls12_381,
                    key_type: Some(KeyType::RecoveryPhrase),
                }],
            },
            receive_address: None,
        }
    }
}

fn side_to_signers(side: &VaultConfigSide) -> Result<crate::vault::SignerSet> {
    let (keys, vault_launcher_ids) = keys_from_config_members(&side.members)?;
    if keys.is_empty() && vault_launcher_ids.is_empty() {
        return Err(Error::msg("custody/recovery side has no members"));
    }
    Ok(crate::vault::SignerSet {
        keys,
        vault_launcher_ids,
        threshold: side.threshold as usize,
    })
}

fn side_to_custody(side: &VaultConfigSide) -> Result<CustodyPath> {
    if let Some(hash) = &side.hash {
        return Ok(CustodyPath::Hash(parse_bytes32(hash)?.into()));
    }
    Ok(CustodyPath::Signers(side_to_signers(side)?))
}

fn recovery_to_signers(side: &VaultConfigRecovery) -> Result<crate::vault::RecoverySignerSet> {
    Ok(crate::vault::RecoverySignerSet {
        set: side_to_signers(&VaultConfigSide {
            threshold: side.threshold,
            members: side.members.clone(),
            hash: None,
        })?,
        clawback_timelock: side.clawback_timelock,
    })
}

fn member_key(curve: Curve, public_key_hex: &str) -> Result<VaultMemberKey> {
    match curve {
        Curve::Bls12_381 => Ok(VaultMemberKey::Bls(parse_bls_public_key(public_key_hex)?)),
        Curve::Secp256r1 | Curve::Webauthn => {
            let bytes = parse_hex_bytes(public_key_hex)?;
            let arr: [u8; 33] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::msg("secp/passkey public key must be 33 compressed bytes"))?;
            let pk = chia_secp::R1PublicKey::from_bytes(&arr)
                .map_err(|e| Error::msg(format!("invalid R1 public key: {e}")))?;
            Ok(if curve == Curve::Webauthn {
                VaultMemberKey::Passkey(pk)
            } else {
                VaultMemberKey::R1(pk)
            })
        }
        Curve::Secp256k1 => {
            let bytes = parse_hex_bytes(public_key_hex)?;
            let arr: [u8; 33] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| Error::msg("secp256k1 public key must be 33 compressed bytes"))?;
            let pk = chia_secp::K1PublicKey::from_bytes(&arr)
                .map_err(|e| Error::msg(format!("invalid K1 public key: {e}")))?;
            Ok(VaultMemberKey::K1(pk))
        }
    }
}

pub fn parse_bytes32(hex_str: &str) -> Result<Bytes32> {
    let bytes = parse_hex_bytes(hex_str)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::msg("expected 32-byte hex value"))?;
    Ok(Bytes32::new(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cloud_wallet_shaped_config() {
        let json = r#"{
          "launcherId": "0x1111111111111111111111111111111111111111111111111111111111111111",
          "custody": {
            "threshold": 1,
            "members": [
              {
                "type": "publicKey",
                "publicKey": "0x02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "curve": "WEBAUTHN",
                "keyType": "PASSKEY"
              }
            ]
          },
          "recovery": {
            "threshold": 1,
            "clawbackTimelock": 43200,
            "members": [
              {
                "type": "publicKey",
                "publicKey": "0xb6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6",
                "curve": "BLS12_381",
                "keyType": "RECOVERY_PHRASE"
              }
            ]
          }
        }"#;
        let config: VaultConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.recovery.clawback_timelock, 43200);
        assert!(config.receive_address.is_none());
        assert!(matches!(
            config.custody.members[0],
            VaultConfigMember::PublicKey {
                curve: Curve::Webauthn,
                ..
            }
        ));
    }

    #[test]
    fn recorded_receive_address_rejects_hex_launcher_id() {
        use crate::keys::{MnemonicWordCount, generate_mnemonic};

        let custody = generate_mnemonic(MnemonicWordCount::Words12).unwrap();
        let recovery = generate_mnemonic(MnemonicWordCount::Words12).unwrap();
        let mut config = VaultConfig::from_bls_pair(
            Bytes32::new([0x11; 32]),
            &custody.key_pair,
            &recovery.key_pair,
            43_200,
        );
        config.receive_address = Some(format!("0x{}", hex::encode([0x22; 32])));
        assert!(config.recorded_receive_address().is_err());
    }
}
