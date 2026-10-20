//! Veridag Ethereum Infrastructure Substrate (spec 20).
//!
//! Provides:
//! 1. Cross-chain bridge data structures and monotonic deposit/withdrawal tracking.
//! 2. BMH-1 Merkle inclusion proof generation formatted for Ethereum L1 smart contracts (`VeridagLightClient.sol`).
//! 3. High-throughput EVM JSON-RPC provider (`eth_*`, `net_*`, `web3_*`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use thiserror::Error;
use veridag_checkpoint::Checkpoint;
use veridag_codec::{Decode, DecodeError, Decoder, Encode, Encoder};
use veridag_crypto::hash;
use veridag_merkle::{leaf_hash, prove, verify, InclusionProof};
use veridag_object_state::ObjectState;
use veridag_protocol_types::{Address, EthAddress, EthTxHash, Hash, ObjectId};
use veridag_stablecoin::StablecoinAccountPayload;

/// Domain separator for Ethereum bridge messages.
pub const ETH_BRIDGE_DOMAIN: &str = "VERIDAG_ETH_BRIDGE_V1";

/// Default EVM Chain ID for Veridag L2 execution (0x5645 = 22085).
pub const DEFAULT_EVM_CHAIN_ID: u64 = 22085;

/// Errors arising from Ethereum infrastructure operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EthereumError {
    /// Deserialization or serialization failure.
    #[error("codec error: {0}")]
    Codec(#[from] DecodeError),
    /// Invalid JSON-RPC request syntax.
    #[error("invalid json-rpc request: {0}")]
    InvalidRpc(String),
    /// Account not found for query.
    #[error("account not found")]
    AccountNotFound,
    /// Merkle inclusion proof generation failed.
    #[error("merkle proof generation error")]
    MerkleProofFailed,
    /// Proof verification failed.
    #[error("inclusion proof failed validation")]
    InvalidProof,
}

/// A cross-chain deposit message initiated on Ethereum L1 (`VeridagBridge.sol`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CrossChainDeposit {
    /// L1 sender address (20 bytes).
    pub l1_sender: EthAddress,
    /// Destination address on Veridag (32 bytes).
    pub l2_recipient: Address,
    /// Amount of USDV or asset deposited (micro-units, 6 decimals).
    pub amount: u128,
    /// Ethereum L1 block number containing the event.
    pub l1_block_number: u64,
    /// Ethereum L1 transaction hash.
    pub l1_tx_hash: EthTxHash,
    /// Monotonic bridge sequence number.
    pub sequence: u64,
}

impl Encode for CrossChainDeposit {
    fn encode(&self, e: &mut Encoder) {
        self.l1_sender.encode(e);
        e.fixed(&self.l2_recipient);
        e.u128(self.amount);
        e.u64(self.l1_block_number);
        self.l1_tx_hash.encode(e);
        e.u64(self.sequence);
    }
}

impl Decode for CrossChainDeposit {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            l1_sender: EthAddress::decode(d)?,
            l2_recipient: d.fixed::<32>()?,
            amount: d.u128()?,
            l1_block_number: d.u64()?,
            l1_tx_hash: EthTxHash::decode(d)?,
            sequence: d.u64()?,
        })
    }
}

impl CrossChainDeposit {
    /// Compute unique hash identifier for this deposit message.
    pub fn message_hash(&self) -> Hash {
        let mut enc = Encoder::new();
        self.encode(&mut enc);
        hash(ETH_BRIDGE_DOMAIN, &enc.into_bytes())
    }

    /// Calculate the net minted USDV amount and protocol bridge liquidity surcharge.
    /// Default fee is 5 bps (0.05% = 5 / 10,000).
    pub fn calculate_net_and_surcharge(&self, fee_bps: u64) -> (u128, u128) {
        let surcharge = (self.amount * fee_bps as u128) / 10_000;
        let net = self.amount.saturating_sub(surcharge);
        (net, surcharge)
    }
}

/// A cross-chain withdrawal message initiated on Veridag for release on Ethereum L1.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CrossChainWithdrawal {
    /// Veridag L2 sender address.
    pub l2_sender: Address,
    /// Destination Ethereum L1 address.
    pub l1_recipient: EthAddress,
    /// Amount of USDV to release (micro-units, 6 decimals).
    pub amount: u128,
    /// Checkpoint sequence containing the committed burn.
    pub checkpoint_sequence: u64,
    /// Monotonic withdrawal sequence number.
    pub sequence: u64,
}

impl Encode for CrossChainWithdrawal {
    fn encode(&self, e: &mut Encoder) {
        e.fixed(&self.l2_sender);
        self.l1_recipient.encode(e);
        e.u128(self.amount);
        e.u64(self.checkpoint_sequence);
        e.u64(self.sequence);
    }
}

impl Decode for CrossChainWithdrawal {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            l2_sender: d.fixed::<32>()?,
            l1_recipient: EthAddress::decode(d)?,
            amount: d.u128()?,
            checkpoint_sequence: d.u64()?,
            sequence: d.u64()?,
        })
    }
}

impl CrossChainWithdrawal {
    /// Compute unique hash identifier for this withdrawal.
    pub fn message_hash(&self) -> Hash {
        let mut enc = Encoder::new();
        self.encode(&mut enc);
        hash(ETH_BRIDGE_DOMAIN, &enc.into_bytes())
    }

    /// Calculate the net released L1 amount and protocol bridge liquidity surcharge.
    /// Default fee is 5 bps (0.05% = 5 / 10,000).
    pub fn calculate_net_and_surcharge(&self, fee_bps: u64) -> (u128, u128) {
        let surcharge = (self.amount * fee_bps as u128) / 10_000;
        let net = self.amount.saturating_sub(surcharge);
        (net, surcharge)
    }
}

/// Cryptographic state proof formatted for `VeridagLightClient.sol` on Ethereum.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BridgeStateProof {
    /// Target object id.
    pub object_id: String,
    /// Raw object payload (hex-encoded).
    pub object_data: String,
    /// Checkpoint state root (hex-encoded `0x...`).
    pub state_root: String,
    /// Checkpoint sequence number.
    pub checkpoint_sequence: u64,
    /// Sibling hashes along the BMH-1 path (`bytes32[]` in Solidity).
    pub proof_hashes: Vec<String>,
    /// Flags indicating left/right path at each level.
    pub right_flags: Vec<bool>,
    /// Leaf index in the canonical Merkle tree.
    pub leaf_index: usize,
}

impl BridgeStateProof {
    /// Generate an inclusion proof for a target object directly from state.
    pub fn generate(
        state: &ObjectState,
        target_id: &ObjectId,
        checkpoint: &Checkpoint,
    ) -> Result<Self, EthereumError> {
        let mut leaves: Vec<(ObjectId, Hash)> = state
            .iter()
            .map(|(id, obj)| (*id, leaf_hash(id, &obj.to_bytes())))
            .collect();
        leaves.sort_by_key(|(id, _)| *id);

        let target_bytes = state
            .get(target_id)
            .ok_or(EthereumError::AccountNotFound)?
            .to_bytes();

        let leaf_idx = leaves
            .iter()
            .position(|(id, _)| id == target_id)
            .ok_or(EthereumError::MerkleProofFailed)?;

        let proof = prove(&leaves, leaf_idx).ok_or(EthereumError::MerkleProofFailed)?;

        let proof_hexes = proof
            .siblings
            .iter()
            .map(|h| format!("0x{}", hex::encode(h)))
            .collect();

        Ok(Self {
            object_id: format!("0x{}", hex::encode(target_id.as_bytes())),
            object_data: format!("0x{}", hex::encode(&target_bytes)),
            state_root: format!("0x{}", hex::encode(checkpoint.state_root)),
            checkpoint_sequence: checkpoint.sequence,
            proof_hashes: proof_hexes,
            right_flags: proof.right,
            leaf_index: leaf_idx,
        })
    }

    /// Verify this proof locally against the checkpoint state root.
    pub fn verify(&self) -> bool {
        let root_bytes = match hex::decode(self.state_root.trim_start_matches("0x")) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };

        let target_id_bytes = match hex::decode(self.object_id.trim_start_matches("0x")) {
            Ok(b) if b.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&b);
                a
            }
            _ => return false,
        };

        let data_bytes = match hex::decode(self.object_data.trim_start_matches("0x")) {
            Ok(b) => b,
            _ => return false,
        };

        let target_id = ObjectId(target_id_bytes);
        let target_leaf = leaf_hash(&target_id, &data_bytes);
        let siblings: Vec<Hash> = self
            .proof_hashes
            .iter()
            .filter_map(|s| {
                hex::decode(s.trim_start_matches("0x")).ok().and_then(|b| {
                    if b.len() == 32 {
                        let mut a = [0u8; 32];
                        a.copy_from_slice(&b);
                        Some(a)
                    } else {
                        None
                    }
                })
            })
            .collect();

        if siblings.len() != self.proof_hashes.len() || siblings.len() != self.right_flags.len() {
            return false;
        }

        let proof = InclusionProof {
            siblings,
            right: self.right_flags.clone(),
        };

        verify(&target_leaf, &proof, &root_bytes).is_ok()
    }
}

/// Incoming JSON-RPC 2.0 request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    /// JSON-RPC version (must be "2.0").
    pub jsonrpc: String,
    /// Request method name (e.g. `eth_blockNumber`).
    pub method: String,
    /// Optional parameter values.
    #[serde(default)]
    pub params: serde_json::Value,
    /// Request identifier.
    pub id: serde_json::Value,
}

/// Outgoing JSON-RPC 2.0 response payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    /// JSON-RPC version.
    pub jsonrpc: String,
    /// Result payload if successful.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error payload if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    /// Request identifier.
    pub id: serde_json::Value,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    /// Error code.
    pub code: i32,
    /// Error message.
    pub message: String,
}

/// The high-throughput EVM JSON-RPC Provider for Veridag.
#[derive(Clone, Debug)]
pub struct EvmJsonRpcProvider {
    /// Configured EVM Chain ID.
    pub chain_id: u64,
    /// Network ID.
    pub network_id: u64,
    /// Client version string.
    pub client_version: String,
}

impl Default for EvmJsonRpcProvider {
    fn default() -> Self {
        Self {
            chain_id: DEFAULT_EVM_CHAIN_ID,
            network_id: DEFAULT_EVM_CHAIN_ID,
            client_version: "Veridag/v1.0.0-pre-ga/rust".to_string(),
        }
    }
}

impl EvmJsonRpcProvider {
    /// Create a new provider with custom chain ID.
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            network_id: chain_id,
            client_version: "Veridag/v1.0.0-pre-ga/rust".to_string(),
        }
    }

    /// Handle an incoming JSON-RPC string query and produce JSON response.
    pub fn handle_request(
        &self,
        request_body: &str,
        state: &ObjectState,
        latest_sequence: u64,
    ) -> String {
        let req: JsonRpcRequest = match serde_json::from_str(request_body) {
            Ok(r) => r,
            Err(e) => {
                let err_resp = JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("Parse error: {e}"),
                    }),
                    id: serde_json::Value::Null,
                };
                return serde_json::to_string(&err_resp).unwrap();
            }
        };

        let resp = self.dispatch(req, state, latest_sequence);
        serde_json::to_string(&resp).unwrap()
    }

    fn dispatch(
        &self,
        req: JsonRpcRequest,
        state: &ObjectState,
        latest_sequence: u64,
    ) -> JsonRpcResponse {
        let id = req.id.clone();
        match req.method.as_str() {
            "eth_chainId" => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                result: Some(serde_json::Value::String(format!("0x{:x}", self.chain_id))),
                error: None,
                id,
            },
            "net_version" => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                result: Some(serde_json::Value::String(self.network_id.to_string())),
                error: None,
                id,
            },
            "web3_clientVersion" => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                result: Some(serde_json::Value::String(self.client_version.clone())),
                error: None,
                id,
            },
            "eth_blockNumber" => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                result: Some(serde_json::Value::String(format!(
                    "0x{:x}",
                    latest_sequence
                ))),
                error: None,
                id,
            },
            "eth_getBalance" => {
                let balance_hex = self.handle_get_balance(&req.params, state);
                JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    result: Some(serde_json::Value::String(balance_hex)),
                    error: None,
                    id,
                }
            }
            "eth_sendRawTransaction" => {
                // Simulate deterministic ingestion
                let dummy_hash = hash("VERIDAG_ETH_TX_V1", req.params.to_string().as_bytes());
                JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    result: Some(serde_json::Value::String(format!(
                        "0x{}",
                        hex::encode(dummy_hash)
                    ))),
                    error: None,
                    id,
                }
            }
            "eth_call" => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                result: Some(serde_json::Value::String("0x".into())),
                error: None,
                id,
            },
            "eth_gasPrice" => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                result: Some(serde_json::Value::String("0x1".into())),
                error: None,
                id,
            },
            "eth_estimateGas" => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                result: Some(serde_json::Value::String("0x5208".into())),
                error: None,
                id,
            },
            "eth_getTransactionCount" => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                result: Some(serde_json::Value::String("0x0".into())),
                error: None,
                id,
            },
            "eth_getBlockByNumber" => {
                let block_hex = format!("0x{:x}", latest_sequence);
                let root_hex = format!("0x{}", hex::encode(state.state_root()));
                let block_obj = serde_json::json!({
                    "number": block_hex,
                    "hash": root_hex,
                    "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "stateRoot": root_hex,
                    "transactions": [],
                    "timestamp": "0x66000000",
                    "gasLimit": "0x1fffffffffffff",
                    "gasUsed": "0x0"
                });
                JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    result: Some(block_obj),
                    error: None,
                    id,
                }
            }
            _ => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: format!("Method not found: {}", req.method),
                }),
                id,
            },
        }
    }

    fn handle_get_balance(&self, params: &serde_json::Value, state: &ObjectState) -> String {
        let addr_str = params
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("0x0");

        let clean_addr = addr_str.trim_start_matches("0x");
        let decoded = hex::decode(clean_addr).unwrap_or_default();

        if decoded.len() == 20 {
            // Map 20-byte EthAddress into 32-byte Veridag Address (left padded with zeros)
            let mut addr = [0u8; 32];
            addr[12..32].copy_from_slice(&decoded);
            let account_id = veridag_stablecoin::StablecoinLedger::derive_account_id(&addr);

            if let Some(obj) = state.get(&account_id) {
                let mut d = Decoder::new(&obj.payload);
                if let Ok(payload) = StablecoinAccountPayload::decode(&mut d) {
                    return format!("0x{:x}", payload.balance);
                }
            }
        }

        "0x0".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veridag_checkpoint::FinalityProof;
    use veridag_protocol_types::{object_type, CheckpointId, Ownership};

    #[test]
    fn test_cross_chain_deposit_and_withdrawal_codecs() {
        let dep = CrossChainDeposit {
            l1_sender: EthAddress([0x11; 20]),
            l2_recipient: [0x22; 32],
            amount: 50_000 * 1_000_000,
            l1_block_number: 21_000_000,
            l1_tx_hash: EthTxHash([0x33; 32]),
            sequence: 101,
        };

        let mut enc = Encoder::new();
        dep.encode(&mut enc);
        let bytes = enc.into_bytes();

        let mut d = Decoder::new(&bytes);
        let decoded = CrossChainDeposit::decode(&mut d).unwrap();
        assert_eq!(dep, decoded);
        assert_eq!(dep.message_hash(), decoded.message_hash());

        let with = CrossChainWithdrawal {
            l2_sender: [0x44; 32],
            l1_recipient: EthAddress([0x55; 20]),
            amount: 12_500 * 1_000_000,
            checkpoint_sequence: 88,
            sequence: 1,
        };

        let mut enc_w = Encoder::new();
        with.encode(&mut enc_w);
        let w_bytes = enc_w.into_bytes();

        let mut d_w = Decoder::new(&w_bytes);
        let w_decoded = CrossChainWithdrawal::decode(&mut d_w).unwrap();
        assert_eq!(with, w_decoded);
        assert_eq!(with.message_hash(), w_decoded.message_hash());
    }

    #[test]
    fn test_evm_json_rpc_provider() {
        let provider = EvmJsonRpcProvider::default();
        let state = ObjectState::new();

        // 1. eth_chainId
        let req_chain_id = r#"{"jsonrpc":"2.0","method":"eth_chainId","id":1}"#;
        let resp = provider.handle_request(req_chain_id, &state, 42);
        let parsed: JsonRpcResponse = serde_json::from_str(&resp).unwrap();
        assert_eq!(parsed.result.unwrap(), "0x5645");

        // 2. eth_blockNumber
        let req_block_num = r#"{"jsonrpc":"2.0","method":"eth_blockNumber","id":2}"#;
        let resp_block = provider.handle_request(req_block_num, &state, 16);
        let parsed_block: JsonRpcResponse = serde_json::from_str(&resp_block).unwrap();
        assert_eq!(parsed_block.result.unwrap(), "0x10");

        // 3. web3_clientVersion
        let req_version = r#"{"jsonrpc":"2.0","method":"web3_clientVersion","id":3}"#;
        let resp_ver = provider.handle_request(req_version, &state, 16);
        let parsed_ver: JsonRpcResponse = serde_json::from_str(&resp_ver).unwrap();
        assert!(parsed_ver
            .result
            .unwrap()
            .as_str()
            .unwrap()
            .contains("Veridag"));

        // 4. eth_gasPrice
        let req_gas = r#"{"jsonrpc":"2.0","method":"eth_gasPrice","id":4}"#;
        let resp_gas = provider.handle_request(req_gas, &state, 16);
        let parsed_gas: JsonRpcResponse = serde_json::from_str(&resp_gas).unwrap();
        assert_eq!(parsed_gas.result.unwrap(), "0x1");

        // 5. eth_estimateGas
        let req_est = r#"{"jsonrpc":"2.0","method":"eth_estimateGas","id":5}"#;
        let resp_est = provider.handle_request(req_est, &state, 16);
        let parsed_est: JsonRpcResponse = serde_json::from_str(&resp_est).unwrap();
        assert_eq!(parsed_est.result.unwrap(), "0x5208");

        // 6. eth_getBlockByNumber
        let req_blk = r#"{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest", false],"id":6}"#;
        let resp_blk = provider.handle_request(req_blk, &state, 128);
        let parsed_blk: JsonRpcResponse = serde_json::from_str(&resp_blk).unwrap();
        assert_eq!(parsed_blk.result.unwrap()["number"], "0x80");
    }

    #[test]
    fn test_cross_chain_surcharge_calculation() {
        let dep = CrossChainDeposit {
            l1_sender: EthAddress([0x11; 20]),
            l2_recipient: [0x22; 32],
            amount: 100_000 * 1_000_000,
            l1_block_number: 21_000_000,
            l1_tx_hash: EthTxHash([0x33; 32]),
            sequence: 101,
        };
        // 5 bps = 0.05%
        let (net, surcharge) = dep.calculate_net_and_surcharge(5);
        assert_eq!(surcharge, 50 * 1_000_000);
        assert_eq!(net, 99_950 * 1_000_000);
        assert_eq!(net + surcharge, dep.amount);
    }

    #[test]
    fn test_bridge_state_proof_generation_and_verification() {
        let mut state = ObjectState::new();
        let id = ObjectId([0xaa; 32]);
        let obj = veridag_object_state::Object::new(
            id,
            object_type::STABLECOIN,
            Ownership::Address([0xbb; 32]),
            vec![1, 2, 3, 4],
            vec![],
        );
        state.create(obj).unwrap();

        let cp = Checkpoint {
            protocol_version: 1,
            chain_id: 1,
            epoch: 1,
            sequence: 5,
            previous_checkpoint: CheckpointId::ZERO,
            state_root: state.state_root(),
            transaction_root: [0u8; 32],
            object_root: state.state_root(),
            dag_commitment: [0u8; 32],
            validator_set_commitment: [0u8; 32],
            finality_proof: FinalityProof::default(),
        };

        let proof =
            BridgeStateProof::generate(&state, &id, &cp).expect("proof generation must succeed");

        assert!(proof.verify(), "generated proof must verify locally");
    }
}
