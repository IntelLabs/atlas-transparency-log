//! # Atlas Transparency Log
//!
//! A transparency log implementation with Merkle tree support for C2PA manifests.
//!
//! ## Overview
//!
//! This library provides:
//! - Merkle tree implementation with inclusion and consistency proofs
//! - Content format detection (JSON, CBOR, Binary)
//! - Cryptographic signing and verification
//! - Manifest storage and retrieval
//!
//! ## Example
//!
//! ```rust
//! use atlas_transparency_log::merkle_tree::{MerkleTree, LogLeaf};
//! use chrono::Utc;
//!
//! let mut tree = MerkleTree::new();
//! let leaf = LogLeaf::new(
//!     "content_hash".to_string(),
//!     "manifest_id".to_string(),
//!     1,
//!     Utc::now(),
//! );
//! tree.add_leaf(leaf);
//!
//! // Generate inclusion proof
//! let proof = tree.generate_inclusion_proof("manifest_id").unwrap();
//! assert!(tree.verify_inclusion_proof(&proof));
//! ```

pub mod merkle_tree;

use actix_web::HttpRequest;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};

pub use atlas_common::hash::calculate_hash;
pub use atlas_common::validation::validate_manifest_id;

/// Content format enumeration for manifests
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ContentFormat {
    #[serde(rename = "json")]
    JSON,
    #[serde(rename = "cbor")]
    CBOR,
    #[serde(rename = "binary")]
    Binary,
}

impl Default for ContentFormat {
    fn default() -> Self {
        ContentFormat::JSON
    }
}

/// Detect content type from HTTP request headers
///
/// # Example
///
/// ```rust
/// # use atlas_transparency_log::ContentFormat;
/// // This would typically be used with an actual HttpRequest
/// // let format = detect_content_type(&req);
/// ```
pub fn detect_content_type(req: &HttpRequest) -> ContentFormat {
    use actix_web::http::header;

    if let Some(content_type) = req.headers().get(header::CONTENT_TYPE) {
        match content_type.to_str() {
            Ok(ct) => {
                if ct.contains("application/cbor") {
                    return ContentFormat::CBOR;
                } else if ct.contains("application/octet-stream") {
                    return ContentFormat::Binary;
                }
            }
            Err(_) => {}
        }
    }
    ContentFormat::JSON
}

/// Hash binary data using the default algorithm (SHA384)
///
/// # Example
///
/// ```rust
/// use atlas_transparency_log::hash_binary;
///
/// let data = b"hello world";
/// let hash = hash_binary(data);
/// assert_eq!(hash.len(), 96); // SHA384 produces 96 hex characters
/// ```
pub fn hash_binary(data: &[u8]) -> String {
    calculate_hash(data)
}

/// Sign binary data with Ed25519
///
/// # Example
///
/// ```rust
/// use atlas_transparency_log::sign_data;
/// use ring::signature::Ed25519KeyPair;
///
/// let rng = ring::rand::SystemRandom::new();
/// let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
/// let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();
///
/// let data = b"test data";
/// let signature = sign_data(&key_pair, data);
/// assert!(!signature.is_empty());
/// ```
pub fn sign_data(key_pair: &Ed25519KeyPair, data: &[u8]) -> String {
    let signature = key_pair.sign(data);
    STANDARD.encode(signature.as_ref())
}

/// Validate manifest ID format
///
/// # Example
///
/// ```rust
/// use atlas_transparency_log::is_valid_manifest_id;
///
/// assert!(is_valid_manifest_id("urn:c2pa:123e4567-e89b-12d3-a456-426614174000"));
/// assert!(is_valid_manifest_id("my-manifest-123"));
/// assert!(!is_valid_manifest_id("invalid manifest"));
/// ```
pub fn is_valid_manifest_id(id: &str) -> bool {
    validate_manifest_id(id).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_format_default() {
        assert_eq!(ContentFormat::default(), ContentFormat::JSON);
    }

    #[test]
    fn test_hash_binary() {
        let data = b"test data";
        let hash = hash_binary(data);
        assert_eq!(hash.len(), 96); // SHA384

        // Same input should produce same hash
        assert_eq!(hash, hash_binary(data));
    }

    #[test]
    fn test_sign_data() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

        let data = b"test data";
        let signature = sign_data(&key_pair, data);

        assert!(!signature.is_empty());
        // Ed25519 signatures are 64 bytes, encoded as base64
        let decoded = STANDARD.decode(&signature).unwrap();
        assert_eq!(decoded.len(), 64);
    }

    #[test]
    fn test_manifest_id_validation() {
        assert!(is_valid_manifest_id(
            "urn:c2pa:123e4567-e89b-12d3-a456-426614174000"
        ));
        assert!(is_valid_manifest_id("my-manifest-123"));
        assert!(!is_valid_manifest_id("invalid manifest"));
        assert!(!is_valid_manifest_id(""));
    }
}
