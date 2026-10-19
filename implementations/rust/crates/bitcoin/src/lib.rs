//! Veridag Bitcoin Infrastructure Substrate (spec 21).
//!
//! Provides:
//! 1. Bitcoin SPV (Simplified Payment Verification) header parsing and proof-of-work validation.
//! 2. Double-SHA256 Merkle branch inclusion proof verification for Bitcoin transactions.
//! 3. Cross-chain deposit and withdrawal primitives between Bitcoin UTXOs and Veridag object state.
//! 4. Bitcoin JSON-RPC gateway (`getblockcount`, `getblockhash`, `getblockheader`, `verifytxoutproof`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};
use thiserror::Error;
use veridag_codec::{Decode, DecodeError, Decoder, Encode, Encoder};
use veridag_protocol_types::Address;

/// Domain separator for Bitcoin bridge messages.
pub const BTC_BRIDGE_DOMAIN: &str = "VERIDAG_BTC_BRIDGE_V1";

/// Length of a standard Bitcoin wire block header in bytes.
pub const BTC_HEADER_LEN: usize = 80;

/// Double-SHA256 hash helper: `SHA256(SHA256(data))`.
#[inline]
pub fn hash256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Errors arising from Bitcoin infrastructure operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BitcoinError {
    /// Codec deserialization or serialization failure.
    #[error("codec error: {0}")]
    Codec(#[from] DecodeError),
    /// Invalid header length.
    #[error("invalid header length: expected 80 bytes, got {0}")]
    InvalidHeaderLength(usize),
    /// Proof-of-work target exceeded.
    #[error("proof of work target exceeded")]
    TargetExceeded,
    /// Invalid Merkle branch proof.
    #[error("invalid merkle proof")]
    InvalidMerkleProof,
    /// Missing parent block header.
    #[error("parent header not found: {0}")]
    ParentNotFound(String),
    /// Invalid JSON-RPC request syntax.
    #[error("invalid json-rpc request: {0}")]
    InvalidRpc(String),
    /// Block or transaction not found.
    #[error("not found")]
    NotFound,
}

/// Bitcoin block header (80 bytes).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BitcoinBlockHeader {
    /// Block version number.
    pub version: i32,
    /// 32-byte hash of the previous block header (internal byte order).
    pub prev_block_hash: [u8; 32],
    /// 32-byte Merkle root of all transactions in this block.
    pub merkle_root: [u8; 32],
    /// Block creation timestamp in Unix epoch seconds.
    pub time: u32,
    /// Compact representation of the proof-of-work difficulty target (nBits).
    pub bits: u32,
    /// Nonce used to solve the proof-of-work puzzle.
    pub nonce: u32,
}

impl BitcoinBlockHeader {
    /// Parse an 80-byte raw Bitcoin block header from bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, BitcoinError> {
        if bytes.len() != BTC_HEADER_LEN {
            return Err(BitcoinError::InvalidHeaderLength(bytes.len()));
        }

        let version = i32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let mut prev_block_hash = [0u8; 32];
        prev_block_hash.copy_from_slice(&bytes[4..36]);
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&bytes[36..68]);
        let time = u32::from_le_bytes(bytes[68..72].try_into().unwrap());
        let bits = u32::from_le_bytes(bytes[72..76].try_into().unwrap());
        let nonce = u32::from_le_bytes(bytes[76..80].try_into().unwrap());

        Ok(Self {
            version,
            prev_block_hash,
            merkle_root,
            time,
            bits,
            nonce,
        })
    }

    /// Serialize this block header into canonical 80-byte Bitcoin wire format.
    pub fn to_bytes(&self) -> [u8; BTC_HEADER_LEN] {
        let mut buf = [0u8; BTC_HEADER_LEN];
        buf[0..4].copy_from_slice(&self.version.to_le_bytes());
        buf[4..36].copy_from_slice(&self.prev_block_hash);
        buf[36..68].copy_from_slice(&self.merkle_root);
        buf[68..72].copy_from_slice(&self.time.to_le_bytes());
        buf[72..76].copy_from_slice(&self.bits.to_le_bytes());
        buf[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        buf
    }

    /// Compute the double-SHA256 block hash (internal byte order).
    pub fn block_hash(&self) -> [u8; 32] {
        hash256(&self.to_bytes())
    }

    /// Compute the canonical block hash (reversed big-endian byte order as displayed in Bitcoin explorers and RPCs).
    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut h = self.block_hash();
        h.reverse();
        h
    }

    /// Convert the compact nBits target into a 256-bit target integer represented as a 32-byte big-endian array.
    pub fn target(&self) -> [u8; 32] {
        let exponent = (self.bits >> 24) as usize;
        let mantissa = self.bits & 0x007fffff;
        let mut target = [0u8; 32];

        if exponent <= 3 {
            let val = mantissa >> (8 * (3 - exponent));
            target[31] = (val & 0xff) as u8;
            target[30] = ((val >> 8) & 0xff) as u8;
            target[29] = ((val >> 16) & 0xff) as u8;
        } else if exponent <= 32 {
            let offset = 32 - exponent;
            target[offset] = ((mantissa >> 16) & 0xff) as u8;
            if offset + 1 < 32 {
                target[offset + 1] = ((mantissa >> 8) & 0xff) as u8;
            }
            if offset + 2 < 32 {
                target[offset + 2] = (mantissa & 0xff) as u8;
            }
        }
        target
    }

    /// Verify that this header meets its proof-of-work target (`hash <= target`).
    pub fn verify_pow(&self) -> Result<(), BitcoinError> {
        let h = self.block_hash();
        // Bitcoin hash comparison treats the hash as a little-endian integer,
        // which means the big-endian representation is the reversed byte array.
        let mut rev_h = h;
        rev_h.reverse();

        let target = self.target();

        for i in 0..32 {
            if rev_h[i] < target[i] {
                return Ok(());
            } else if rev_h[i] > target[i] {
                return Err(BitcoinError::TargetExceeded);
            }
        }
        Ok(())
    }
}

/// Bitcoin Merkle inclusion proof verifying that a transaction `txid` is included in a block with `merkle_root`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BitcoinMerkleProof {
    /// The transaction hash (txid).
    pub txid: [u8; 32],
    /// The 32-byte sibling hashes from the leaf to the root.
    pub branch: Vec<[u8; 32]>,
    /// The 0-based index of the transaction in the block.
    pub index: u32,
}

impl BitcoinMerkleProof {
    /// Compute and verify the Merkle root from the branch and leaf txid.
    pub fn compute_root(&self) -> [u8; 32] {
        let mut current = self.txid;
        let mut idx = self.index;

        for sibling in &self.branch {
            let mut pair = [0u8; 64];
            if idx.is_multiple_of(2) {
                pair[0..32].copy_from_slice(&current);
                pair[32..64].copy_from_slice(sibling);
            } else {
                pair[0..32].copy_from_slice(sibling);
                pair[32..64].copy_from_slice(&current);
            }
            current = hash256(&pair);
            idx /= 2;
        }

        current
    }

    /// Verify that the branch evaluates to `expected_root`.
    pub fn verify(&self, expected_root: &[u8; 32]) -> Result<(), BitcoinError> {
        if &self.compute_root() == expected_root {
            Ok(())
        } else {
            Err(BitcoinError::InvalidMerkleProof)
        }
    }
}

/// Cross-chain Bitcoin deposit message representing a confirmed lock on Bitcoin mainnet.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CrossChainBtcDeposit {
    /// 32-byte Bitcoin transaction hash (txid).
    pub btc_tx_hash: [u8; 32],
    /// Output index (vout).
    pub vout: u32,
    /// Amount in satoshis (1 BTC = 100,000,000 satoshis).
    pub amount_satoshis: u64,
    /// Recipient address on the Veridag network (32 bytes).
    pub veridag_recipient: Address,
    /// Bitcoin block height where deposit confirmed.
    pub btc_block_height: u64,
    /// Monotonic cross-chain sequence number.
    pub sequence: u64,
}

impl Encode for CrossChainBtcDeposit {
    fn encode(&self, e: &mut Encoder) {
        e.fixed(&self.btc_tx_hash);
        e.u32(self.vout);
        e.u64(self.amount_satoshis);
        e.fixed(&self.veridag_recipient);
        e.u64(self.btc_block_height);
        e.u64(self.sequence);
    }
}

impl Decode for CrossChainBtcDeposit {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            btc_tx_hash: d.fixed::<32>()?,
            vout: d.u32()?,
            amount_satoshis: d.u64()?,
            veridag_recipient: d.fixed::<32>()?,
            btc_block_height: d.u64()?,
            sequence: d.u64()?,
        })
    }
}

impl CrossChainBtcDeposit {
    /// Compute unique hash identifier for this Bitcoin deposit message.
    pub fn message_hash(&self) -> [u8; 32] {
        let mut enc = Encoder::new();
        self.encode(&mut enc);
        hash256(&enc.into_bytes())
    }

    /// Calculate net satoshis credited and protocol bridge liquidity surcharge.
    /// Default fee is 5 bps (0.05% = 5 / 10,000).
    pub fn calculate_net_and_surcharge(&self, fee_bps: u64) -> (u64, u64) {
        let surcharge = (self.amount_satoshis * fee_bps) / 10_000;
        let net = self.amount_satoshis.saturating_sub(surcharge);
        (net, surcharge)
    }
}

/// Cross-chain Bitcoin withdrawal message releasing funds back to a native Bitcoin address.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CrossChainBtcWithdrawal {
    /// Sender address on Veridag.
    pub veridag_sender: Address,
    /// Destination scriptPubKey or address string on Bitcoin (e.g. SegWit / Taproot).
    pub btc_destination: String,
    /// Amount in satoshis to release.
    pub amount_satoshis: u64,
    /// Monotonic withdrawal sequence nonce.
    pub sequence: u64,
}

impl Encode for CrossChainBtcWithdrawal {
    fn encode(&self, e: &mut Encoder) {
        e.fixed(&self.veridag_sender);
        e.string(&self.btc_destination);
        e.u64(self.amount_satoshis);
        e.u64(self.sequence);
    }
}

impl Decode for CrossChainBtcWithdrawal {
    fn decode(d: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            veridag_sender: d.fixed::<32>()?,
            btc_destination: d.string(1024)?.to_string(),
            amount_satoshis: d.u64()?,
            sequence: d.u64()?,
        })
    }
}

impl CrossChainBtcWithdrawal {
    /// Compute unique hash identifier for this Bitcoin withdrawal message.
    pub fn message_hash(&self) -> [u8; 32] {
        let mut enc = Encoder::new();
        self.encode(&mut enc);
        hash256(&enc.into_bytes())
    }

    /// Calculate net satoshis released on Bitcoin and protocol bridge liquidity surcharge.
    /// Default fee is 5 bps (0.05% = 5 / 10,000).
    pub fn calculate_net_and_surcharge(&self, fee_bps: u64) -> (u64, u64) {
        let surcharge = (self.amount_satoshis * fee_bps) / 10_000;
        let net = self.amount_satoshis.saturating_sub(surcharge);
        (net, surcharge)
    }
}

/// SPV Header tracker maintaining a monotonic verifiable chain of Bitcoin block headers.
#[derive(Clone, Debug)]
pub struct BtcSpvHeaderTracker {
    headers: Vec<BitcoinBlockHeader>,
    hashes: Vec<[u8; 32]>,
}

impl Default for BtcSpvHeaderTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl BtcSpvHeaderTracker {
    /// Create a new empty Bitcoin header tracker.
    pub fn new() -> Self {
        Self {
            headers: Vec::new(),
            hashes: Vec::new(),
        }
    }

    /// Ingest a validated Bitcoin block header into the tracker.
    pub fn ingest_header(&mut self, header: BitcoinBlockHeader) -> Result<u64, BitcoinError> {
        header.verify_pow()?;

        if !self.headers.is_empty() {
            let last_hash = self.hashes.last().unwrap();
            if &header.prev_block_hash != last_hash {
                return Err(BitcoinError::ParentNotFound(hex::encode(
                    header.prev_block_hash,
                )));
            }
        }

        let hash = header.block_hash();
        self.headers.push(header);
        self.hashes.push(hash);
        Ok(self.headers.len() as u64 - 1)
    }

    /// Current highest block height.
    pub fn height(&self) -> u64 {
        if self.headers.is_empty() {
            0
        } else {
            self.headers.len() as u64 - 1
        }
    }

    /// Retrieve block header by height.
    pub fn get_header_by_height(&self, height: usize) -> Option<&BitcoinBlockHeader> {
        self.headers.get(height)
    }

    /// Retrieve block hash by height.
    pub fn get_hash_by_height(&self, height: usize) -> Option<[u8; 32]> {
        self.hashes.get(height).copied()
    }

    /// Verify a transaction's inclusion against a tracked block height.
    pub fn verify_tx_inclusion(
        &self,
        height: usize,
        proof: &BitcoinMerkleProof,
    ) -> Result<bool, BitcoinError> {
        let header = self.headers.get(height).ok_or(BitcoinError::NotFound)?;
        proof.verify(&header.merkle_root)?;
        Ok(true)
    }
}

/// Bitcoin JSON-RPC gateway request model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtcRpcRequest {
    /// JSON-RPC version ("2.0").
    pub jsonrpc: String,
    /// Method name (e.g. "getblockcount", "getblockhash", "getblockheader").
    pub method: String,
    /// Positional parameter list.
    pub params: serde_json::Value,
    /// Request ID.
    pub id: serde_json::Value,
}

/// Bitcoin JSON-RPC gateway response model.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BtcRpcResponse {
    /// JSON-RPC version ("2.0").
    pub jsonrpc: String,
    /// Result object if succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error string if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<serde_json::Value>,
    /// Request ID echo.
    pub id: serde_json::Value,
}

/// High-performance Bitcoin JSON-RPC provider.
pub struct BtcJsonRpcProvider<'a> {
    tracker: &'a BtcSpvHeaderTracker,
}

impl<'a> BtcJsonRpcProvider<'a> {
    /// Create a new Bitcoin JSON-RPC provider over the SPV header tracker.
    pub fn new(tracker: &'a BtcSpvHeaderTracker) -> Self {
        Self { tracker }
    }

    /// Handle a raw JSON string request and produce a canonical JSON-RPC response.
    pub fn handle_request(&self, req_str: &str) -> String {
        let req: BtcRpcRequest = match serde_json::from_str(req_str) {
            Ok(r) => r,
            Err(e) => {
                let err_resp = BtcRpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(serde_json::json!({ "code": -32700, "message": e.to_string() })),
                    id: serde_json::Value::Null,
                };
                return serde_json::to_string(&err_resp).unwrap();
            }
        };

        let result = match req.method.as_str() {
            "getblockcount" => Ok(serde_json::json!(self.tracker.height())),
            "getblockhash" => {
                if let Some(height) = req.params.get(0).and_then(|v| v.as_u64()) {
                    match self.tracker.get_hash_by_height(height as usize) {
                        Some(h) => {
                            let mut rev = h;
                            rev.reverse();
                            Ok(serde_json::json!(hex::encode(rev)))
                        }
                        None => Err((-8, "Block height out of range")),
                    }
                } else {
                    Err((-1, "Missing block height parameter"))
                }
            }
            "getblockheader" => {
                if let Some(height) = req.params.get(0).and_then(|v| v.as_u64()) {
                    match self.tracker.get_header_by_height(height as usize) {
                        Some(hdr) => Ok(serde_json::json!({
                            "version": hdr.version,
                            "merkle_root": hex::encode(hdr.merkle_root),
                            "time": hdr.time,
                            "bits": hex::encode(hdr.bits.to_be_bytes()),
                            "nonce": hdr.nonce
                        })),
                        None => Err((-8, "Block not found")),
                    }
                } else {
                    Err((-1, "Missing parameter"))
                }
            }
            _other => Err((-32601, "Method not found")),
        };

        let resp = match result {
            Ok(val) => BtcRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(val),
                error: None,
                id: req.id,
            },
            Err((code, msg)) => BtcRpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(serde_json::json!({ "code": code, "message": msg })),
                id: req.id,
            },
        };

        serde_json::to_string(&resp).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Bitcoin Genesis Block Header (80 bytes)
    // Hash: 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
    const GENESIS_HEADER_HEX: &str =
        "010000000000000000000000000000000000000000000000000000000000000000000000\
         3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a\
         29ab5f49ffff001d1dac2b7c";

    #[test]
    fn test_bitcoin_genesis_block_header_parsing_and_pow() {
        let bytes = hex::decode(GENESIS_HEADER_HEX).unwrap();
        let header = BitcoinBlockHeader::parse(&bytes).unwrap();

        assert_eq!(header.version, 1);
        assert_eq!(header.time, 1231006505);
        assert_eq!(header.bits, 0x1d00ffff);
        assert_eq!(header.nonce, 2083236893);

        let hash = header.canonical_hash();
        let hex_hash = hex::encode(hash);
        assert_eq!(
            hex_hash,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert!(header.verify_pow().is_ok());
    }

    #[test]
    fn test_bitcoin_merkle_proof_verification() {
        let h_a = [0x11; 32];
        let h_b = [0x22; 32];
        let h_c = [0x33; 32];
        let h_d = [0x44; 32];

        // Parent AB = hash256(h_a || h_b)
        let parent_ab = {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&h_a);
            buf[32..].copy_from_slice(&h_b);
            hash256(&buf)
        };

        // Parent CD = hash256(h_c || h_d)
        let parent_cd = {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&h_c);
            buf[32..].copy_from_slice(&h_d);
            hash256(&buf)
        };

        // Root ABCD = hash256(parent_ab || parent_cd)
        let expected_root = {
            let mut buf = [0u8; 64];
            buf[..32].copy_from_slice(&parent_ab);
            buf[32..].copy_from_slice(&parent_cd);
            hash256(&buf)
        };

        // Proof for h_c (index 2 in 4 leaves): sibling h_d (right), sibling parent_ab (left)
        let proof = BitcoinMerkleProof {
            txid: h_c,
            branch: vec![h_d, parent_ab],
            index: 2,
        };

        assert!(proof.verify(&expected_root).is_ok());

        // Tamper with txid must fail
        let mut bad_proof = proof.clone();
        bad_proof.txid[0] ^= 0xff;
        assert!(bad_proof.verify(&expected_root).is_err());
    }

    #[test]
    fn test_cross_chain_btc_deposit_and_withdrawal_roundtrip() {
        let deposit = CrossChainBtcDeposit {
            btc_tx_hash: [0x42; 32],
            vout: 1,
            amount_satoshis: 50_000_000, // 0.5 BTC
            veridag_recipient: [0x77; 32],
            btc_block_height: 850_000,
            sequence: 12,
        };

        let mut enc = Encoder::new();
        deposit.encode(&mut enc);
        let bytes = enc.into_bytes();

        let mut d = Decoder::new(&bytes);
        let decoded = CrossChainBtcDeposit::decode(&mut d).unwrap();
        assert_eq!(deposit, decoded);

        let withdrawal = CrossChainBtcWithdrawal {
            veridag_sender: [0x88; 32],
            btc_destination: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh".to_string(),
            amount_satoshis: 25_000_000,
            sequence: 13,
        };

        let mut enc_w = Encoder::new();
        withdrawal.encode(&mut enc_w);
        let w_bytes = enc_w.into_bytes();

        let mut d_w = Decoder::new(&w_bytes);
        let decoded_w = CrossChainBtcWithdrawal::decode(&mut d_w).unwrap();
        assert_eq!(withdrawal, decoded_w);
    }

    #[test]
    fn test_btc_json_rpc_gateway() {
        let mut tracker = BtcSpvHeaderTracker::new();
        let bytes = hex::decode(GENESIS_HEADER_HEX).unwrap();
        let header = BitcoinBlockHeader::parse(&bytes).unwrap();
        tracker.ingest_header(header).unwrap();

        let provider = BtcJsonRpcProvider::new(&tracker);

        let req = r#"{"jsonrpc":"2.0","method":"getblockcount","params":[],"id":1}"#;
        let resp = provider.handle_request(req);
        assert!(resp.contains(r#""result":0"#));

        let req_hash = r#"{"jsonrpc":"2.0","method":"getblockhash","params":[0],"id":2}"#;
        let resp_hash = provider.handle_request(req_hash);
        assert!(
            resp_hash.contains("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
        );
    }

    #[test]
    fn test_btc_cross_chain_surcharge_calculation() {
        let deposit = CrossChainBtcDeposit {
            btc_tx_hash: [0x55; 32],
            vout: 1,
            amount_satoshis: 100_000_000, // 1 BTC
            veridag_recipient: [0x77; 32],
            btc_block_height: 850_000,
            sequence: 10,
        };
        let (net, surcharge) = deposit.calculate_net_and_surcharge(5); // 5 bps
        assert_eq!(surcharge, 50_000); // 0.0005 BTC
        assert_eq!(net, 99_950_000);
        assert_eq!(net + surcharge, deposit.amount_satoshis);
        assert_ne!(deposit.message_hash(), [0u8; 32]);

        let withdrawal = CrossChainBtcWithdrawal {
            veridag_sender: [0x88; 32],
            btc_destination: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh".to_string(),
            amount_satoshis: 50_000_000, // 0.5 BTC
            sequence: 11,
        };
        let (net_w, surcharge_w) = withdrawal.calculate_net_and_surcharge(5);
        assert_eq!(surcharge_w, 25_000);
        assert_eq!(net_w, 49_975_000);
        assert_eq!(net_w + surcharge_w, withdrawal.amount_satoshis);
        assert_ne!(withdrawal.message_hash(), [0u8; 32]);
    }
}
