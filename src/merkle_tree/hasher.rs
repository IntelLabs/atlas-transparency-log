use atlas_common::hash::{
    calculate_hash_optimized, get_hardware_capabilities, BatchHasher, HashAlgorithm,
};
use std::fmt::Debug;

/// Trait for hashing functionality with optimization support
pub trait Hasher: Send + Sync + Debug {
    fn hash(&self, data: &[u8]) -> String;
    fn hash_batch(&self, data_items: &[&[u8]]) -> Vec<String>;
    fn algorithm(&self) -> HashAlgorithm;
}

/// Hardware-optimized SHA384 hasher implementation
#[derive(Clone, Debug)]
pub struct DefaultHasher;

impl DefaultHasher {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DefaultHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for DefaultHasher {
    fn hash(&self, data: &[u8]) -> String {
        calculate_hash_optimized(data, HashAlgorithm::Sha384)
    }

    fn hash_batch(&self, data_items: &[&[u8]]) -> Vec<String> {
        let batch_hasher = BatchHasher::new();
        batch_hasher.hash_batch(data_items, HashAlgorithm::Sha384)
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha384
    }
}

/// Hardware-optimized SHA512 hasher implementation
#[derive(Clone, Debug)]
pub struct Sha512Hasher;

impl Sha512Hasher {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Sha512Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher for Sha512Hasher {
    fn hash(&self, data: &[u8]) -> String {
        calculate_hash_optimized(data, HashAlgorithm::Sha512)
    }

    fn hash_batch(&self, data_items: &[&[u8]]) -> Vec<String> {
        let batch_hasher = BatchHasher::new();
        batch_hasher.hash_batch(data_items, HashAlgorithm::Sha512)
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Sha512
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_hasher() {
        let hasher = DefaultHasher::new();
        let data = b"test data";
        let hash = hasher.hash(data);

        assert_eq!(hash.len(), 96); // SHA384
        assert_eq!(hasher.algorithm(), HashAlgorithm::Sha384);
    }

    #[test]
    fn test_sha512_hasher() {
        let hasher = Sha512Hasher::new();
        let data = b"test data";
        let hash = hasher.hash(data);

        assert_eq!(hash.len(), 128); // SHA512
        assert_eq!(hasher.algorithm(), HashAlgorithm::Sha512);
    }

    #[test]
    fn test_batch_hashing() {
        let hasher = DefaultHasher::new();
        let data_items = vec![
            b"data1".as_slice(),
            b"data2".as_slice(),
            b"data3".as_slice(),
        ];

        let batch_hashes = hasher.hash_batch(&data_items);
        assert_eq!(batch_hashes.len(), 3);

        // Compare with individual hashing
        for (i, data) in data_items.iter().enumerate() {
            let individual_hash = hasher.hash(data);
            assert_eq!(batch_hashes[i], individual_hash);
        }
    }

    #[test]
    fn test_different_algorithms_produce_different_hashes() {
        let data = b"test data";

        let sha384_hasher = DefaultHasher::new();
        let sha512_hasher = Sha512Hasher::new();

        let sha384_hash = sha384_hasher.hash(data);
        let sha512_hash = sha512_hasher.hash(data);

        assert_ne!(sha384_hash, sha512_hash);
    }

    #[test]
    fn test_hardware_capabilities() {
        let caps = get_hardware_capabilities();
        assert!(caps.cpu_cores > 0);
        assert!(caps.optimal_chunk_size() > 0);
    }

    #[test]
    fn test_hasher_consistency() {
        let hasher = DefaultHasher::new();
        let data = b"consistency test";

        let hash1 = hasher.hash(data);
        let hash2 = hasher.hash(data);

        assert_eq!(hash1, hash2);
    }
}
