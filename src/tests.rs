#[cfg(test)]
mod tests {
    use actix_web;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use chrono::Utc;
    use ring::signature::Ed25519KeyPair;

    use atlas_common::hash::{
        calculate_hash_optimized, calculate_hash_with_algorithm, detect_hash_algorithm,
        get_hardware_capabilities, validate_hash_format, verify_hash, verify_hash_with_algorithm,
        BatchHasher, HashAlgorithm, Hasher,
    };
    use atlas_common::validation::{ensure_c2pa_urn, validate_manifest_id};

    use atlas_transparency_log::merkle_tree::{LogLeaf, MerkleTree};
    use atlas_transparency_log::{hash_binary, hash_binary_with_algorithm, sign_data};

    fn hash_string(data: &str) -> String {
        calculate_hash_optimized(data.as_bytes(), HashAlgorithm::Sha384)
    }

    #[actix_web::test]
    async fn test_optimized_hashing() {
        let data = "test data";
        let optimized_hash = hash_string(data);
        let standard_hash = atlas_common::hash::calculate_hash(data.as_bytes());

        assert_eq!(optimized_hash, standard_hash);
        assert_eq!(optimized_hash.len(), 96);

        let different_data = "different data";
        let different_hash = hash_string(different_data);
        assert_ne!(optimized_hash, different_hash);
    }

    #[actix_web::test]
    async fn test_hardware_capabilities() {
        let caps = get_hardware_capabilities();

        assert!(caps.cpu_cores > 0);
        assert!(caps.optimal_chunk_size() > 0);

        println!("Hardware capabilities:");
        println!("  CPU cores: {}", caps.cpu_cores);
        println!("  Intel SHA-NI: {}", caps.sha_extensions);
        println!("  Intel AVX-512: {}", caps.avx512);
        println!("  ARM crypto: {}", caps.arm_crypto);
        println!(
            "  Optimal chunk size: {} MB",
            caps.optimal_chunk_size() / (1024 * 1024)
        );
    }

    #[actix_web::test]
    async fn test_batch_hashing_performance() {
        let batch_hasher = BatchHasher::new();
        let inputs = vec![
            b"input 1".as_slice(),
            b"input 2".as_slice(),
            b"input 3".as_slice(),
            b"input 4".as_slice(),
            b"input 5".as_slice(),
        ];

        let start = std::time::Instant::now();
        let batch_results = batch_hasher.hash_batch(&inputs, HashAlgorithm::Sha384);
        let batch_duration = start.elapsed();

        let start = std::time::Instant::now();
        let individual_results: Vec<String> = inputs
            .iter()
            .map(|input| calculate_hash_optimized(input, HashAlgorithm::Sha384))
            .collect();
        let individual_duration = start.elapsed();

        assert_eq!(batch_results.len(), individual_results.len());
        for (batch_result, individual_result) in batch_results.iter().zip(individual_results.iter())
        {
            assert_eq!(batch_result, individual_result);
        }

        println!(
            "Batch duration: {:?}, Individual duration: {:?}",
            batch_duration, individual_duration
        );
    }

    #[actix_web::test]
    async fn test_signing() {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).expect("Failed to generate key");
        let key_pair =
            Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).expect("Failed to parse key");

        let data = "test data";
        let signature = sign_data(&key_pair, data.as_bytes());

        assert!(!signature.is_empty());

        let decoded = STANDARD.decode(&signature).unwrap();
        assert_eq!(decoded.len(), 64);
    }

    #[actix_web::test]
    async fn test_merkle_proof_simple() {
        let mut tree = MerkleTree::new();
        let now = Utc::now();

        let leaf1 = LogLeaf::new(
            "content_hash_1".to_string(),
            "manifest_1".to_string(),
            1,
            now,
        );

        let leaf2 = LogLeaf::new(
            "content_hash_2".to_string(),
            "manifest_2".to_string(),
            2,
            now,
        );

        tree.add_leaf(leaf1.clone());
        tree.add_leaf(leaf2.clone());

        assert!(tree.root_hash().is_some());

        let proof = tree.generate_inclusion_proof("manifest_1").unwrap();

        assert_eq!(proof.manifest_id, "manifest_1");
        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.merkle_path.len(), 1);
        assert_eq!(proof.tree_size, 2);

        assert!(tree.verify_inclusion_proof(&proof));

        let proof2 = tree.generate_inclusion_proof("manifest_2").unwrap();
        assert_eq!(proof2.manifest_id, "manifest_2");
        assert_eq!(proof2.leaf_index, 1);
        assert!(tree.verify_inclusion_proof(&proof2));
    }

    #[actix_web::test]
    async fn test_merkle_tree_multiple_leaves() {
        let mut tree = MerkleTree::new();
        let now = Utc::now();

        for i in 0..5 {
            let leaf = LogLeaf::new(
                format!("content_hash_{}", i),
                format!("manifest_{}", i),
                i as u64 + 1,
                now,
            );
            tree.add_leaf(leaf);
        }

        assert_eq!(tree.size(), 5);

        for i in 0..5 {
            let manifest_id = format!("manifest_{}", i);
            let proof = tree.generate_inclusion_proof(&manifest_id).unwrap();

            assert_eq!(proof.manifest_id, manifest_id);
            assert_eq!(proof.tree_size, 5);
            assert_eq!(proof.leaf_index, i);

            assert!(
                tree.verify_inclusion_proof(&proof),
                "Proof verification failed for manifest_{}",
                i
            );
        }
    }

    #[actix_web::test]
    async fn test_merkle_tree_batch_operations() {
        let mut tree = MerkleTree::new();
        let now = Utc::now();

        let leaves: Vec<LogLeaf> = (0..20)
            .map(|i| {
                LogLeaf::new(
                    format!("content_hash_{}", i),
                    format!("manifest_{}", i),
                    i as u64 + 1,
                    now,
                )
            })
            .collect();

        let start = std::time::Instant::now();
        tree.add_leaves(leaves);
        let batch_duration = start.elapsed();

        assert_eq!(tree.size(), 20);

        let mut individual_tree = MerkleTree::new();
        let individual_leaves: Vec<LogLeaf> = (0..20)
            .map(|i| {
                LogLeaf::new(
                    format!("content_hash_{}", i),
                    format!("manifest_{}", i),
                    i as u64 + 1,
                    now,
                )
            })
            .collect();

        let start = std::time::Instant::now();
        for leaf in individual_leaves {
            individual_tree.add_leaf(leaf);
        }
        let individual_duration = start.elapsed();

        assert_eq!(tree.root_hash(), individual_tree.root_hash());

        println!(
            "Batch operation: {:?}, Individual operations: {:?}",
            batch_duration, individual_duration
        );
    }

    #[actix_web::test]
    async fn test_consistency_proof() {
        let mut tree = MerkleTree::new();
        let now = Utc::now();

        let mut roots = Vec::new();

        for i in 0..8 {
            let leaf = LogLeaf::new(
                format!("content_hash_{}", i),
                format!("manifest_{}", i),
                i as u64 + 1,
                now,
            );
            tree.add_leaf(leaf);

            if let Some(root) = tree.root_hash() {
                roots.push(root.clone());
            }
        }

        for old_size in 1..7 {
            for new_size in (old_size + 1)..=8 {
                let proof = tree.generate_consistency_proof(old_size, new_size).unwrap();

                assert_eq!(proof.old_root, roots[old_size - 1]);
                assert_eq!(proof.new_root, roots[new_size - 1]);

                assert!(
                    tree.verify_consistency_proof(&proof),
                    "Consistency proof failed for {} -> {}",
                    old_size,
                    new_size
                );
            }
        }
    }

    #[actix_web::test]
    async fn test_hash_binary_functions() {
        let data = b"test data for hash binary";

        let default_hash = hash_binary(data);
        assert_eq!(default_hash.len(), 96);

        let sha256_hash = hash_binary_with_algorithm(data, HashAlgorithm::Sha256);
        assert_eq!(sha256_hash.len(), 64);

        let sha512_hash = hash_binary_with_algorithm(data, HashAlgorithm::Sha512);
        assert_eq!(sha512_hash.len(), 128);

        assert_ne!(default_hash, sha256_hash);
        assert_ne!(default_hash, sha512_hash);
        assert_ne!(sha256_hash, sha512_hash);

        assert_eq!(
            default_hash,
            hash_binary_with_algorithm(data, HashAlgorithm::Sha384)
        );
    }

    #[actix_web::test]
    async fn test_large_data_optimization() {
        let small_data = vec![0u8; 1024];
        let large_data = vec![0u8; 10 * 1024 * 1024];

        let start = std::time::Instant::now();
        let small_hash = hash_binary(&small_data);
        let small_duration = start.elapsed();

        let start = std::time::Instant::now();
        let large_hash = hash_binary(&large_data);
        let large_duration = start.elapsed();

        assert_eq!(small_hash.len(), 96);
        assert_eq!(large_hash.len(), 96);
        assert_ne!(small_hash, large_hash);

        println!(
            "Small data (1KB): {:?}, Large data (10MB): {:?}",
            small_duration, large_duration
        );

        let throughput_mb_per_sec =
            (10.0 * 1024.0 * 1024.0) / large_duration.as_secs_f64() / (1024.0 * 1024.0);
        println!("Large data throughput: {:.2} MB/s", throughput_mb_per_sec);
    }

    #[actix_web::test]
    async fn test_hash_algorithms() {
        let data = b"test data for algorithms";

        let sha256_hash = calculate_hash_with_algorithm(data, &HashAlgorithm::Sha256);
        assert_eq!(sha256_hash.len(), 64);

        let sha384_hash = calculate_hash_optimized(data, HashAlgorithm::Sha384);
        assert_eq!(sha384_hash.len(), 96);

        let sha512_hash = calculate_hash_optimized(data, HashAlgorithm::Sha512);
        assert_eq!(sha512_hash.len(), 128);

        assert_ne!(sha256_hash, sha384_hash);
        assert_ne!(sha384_hash, sha512_hash);
        assert_ne!(sha256_hash, sha512_hash);
    }

    #[actix_web::test]
    async fn test_hash_verification() {
        let data = b"test data for verification";

        let hash = calculate_hash_optimized(data, HashAlgorithm::Sha384);
        assert!(verify_hash(data, &hash));
        assert!(!verify_hash(b"different data", &hash));

        let sha256_hash = calculate_hash_optimized(data, HashAlgorithm::Sha256);
        assert!(verify_hash_with_algorithm(
            data,
            &sha256_hash,
            &HashAlgorithm::Sha256
        ));
        assert!(!verify_hash_with_algorithm(
            data,
            &sha256_hash,
            &HashAlgorithm::Sha384
        ));
    }

    #[actix_web::test]
    async fn test_hasher_trait() {
        let text = "test string";
        let hash1 = text.hash(HashAlgorithm::Sha256);
        let hash2 = text.to_string().hash(HashAlgorithm::Sha256);
        let hash3 = text.as_bytes().hash(HashAlgorithm::Sha256);

        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);
        assert_eq!(hash1.len(), 64);
    }

    #[actix_web::test]
    async fn test_hash_validation() {
        assert!(validate_hash_format(&"a".repeat(64)).is_ok());
        assert!(validate_hash_format(&"b".repeat(96)).is_ok());
        assert!(validate_hash_format(&"c".repeat(128)).is_ok());

        assert!(validate_hash_format(&"x".repeat(32)).is_err());
        assert!(validate_hash_format(&"g".repeat(64)).is_err());
        assert!(validate_hash_format("not-a-hash").is_err());
    }

    #[actix_web::test]
    async fn test_hash_algorithm_detection() {
        let sha256_hash = "a".repeat(64);
        let sha384_hash = "b".repeat(96);
        let sha512_hash = "c".repeat(128);

        assert_eq!(detect_hash_algorithm(&sha256_hash), HashAlgorithm::Sha256);
        assert_eq!(detect_hash_algorithm(&sha384_hash), HashAlgorithm::Sha384);
        assert_eq!(detect_hash_algorithm(&sha512_hash), HashAlgorithm::Sha512);

        let invalid_hash = "d".repeat(50);
        assert_eq!(detect_hash_algorithm(&invalid_hash), HashAlgorithm::Sha384);
    }

    #[actix_web::test]
    async fn test_manifest_id_validation() {
        assert!(validate_manifest_id("urn:c2pa:123e4567-e89b-12d3-a456-426614174000").is_ok());
        assert!(validate_manifest_id("123e4567-e89b-12d3-a456-426614174000").is_ok());
        assert!(validate_manifest_id("my-manifest-123").is_ok());
        assert!(validate_manifest_id("manifest_456").is_ok());

        assert!(validate_manifest_id("").is_err());
        assert!(validate_manifest_id("manifest with spaces").is_err());
        assert!(validate_manifest_id("manifest#123").is_err());
    }

    #[actix_web::test]
    async fn test_c2pa_urn_utilities() {
        let plain_id = "my-model-123";
        let urn = ensure_c2pa_urn(plain_id);
        assert!(urn.starts_with("urn:c2pa:"));

        let uuid = "123e4567-e89b-12d3-a456-426614174000";
        let wrapped = ensure_c2pa_urn(uuid);
        assert_eq!(wrapped, format!("urn:c2pa:{}", uuid));

        let existing_urn = "urn:c2pa:123e4567-e89b-12d3-a456-426614174000";
        assert_eq!(ensure_c2pa_urn(existing_urn), existing_urn);
    }

    #[actix_web::test]
    async fn test_merkle_tree_hardware_info() {
        let tree = MerkleTree::new();

        let algorithm = tree.hasher_algorithm();
        assert_eq!(algorithm, HashAlgorithm::Sha384);

        let caps = tree.get_hardware_capabilities();
        assert!(caps.cpu_cores > 0);
        assert!(caps.optimal_chunk_size() > 0);
    }

    #[actix_web::test]
    async fn test_optimized_vs_standard_consistency() {
        let test_data = b"consistency test between optimized and standard hashing";

        let optimized = calculate_hash_optimized(test_data, HashAlgorithm::Sha384);
        let standard = atlas_common::hash::calculate_hash(test_data);

        assert_eq!(optimized, standard);

        let optimized_sha256 = calculate_hash_optimized(test_data, HashAlgorithm::Sha256);
        let standard_sha256 = calculate_hash_with_algorithm(test_data, &HashAlgorithm::Sha256);

        assert_eq!(optimized_sha256, standard_sha256);
    }

    #[actix_web::test]
    async fn test_tree_persistence_and_integrity() {
        let mut original_tree = MerkleTree::new();
        let now = Utc::now();

        for i in 0..5 {
            original_tree.add_leaf(LogLeaf::new(
                format!("hash_{}", i),
                format!("id_{}", i),
                i as u64,
                now,
            ));
        }

        let original_root = original_tree.root_hash().unwrap().clone();
        let original_size = original_tree.size();

        let leaves = original_tree.leaves().to_vec();
        let restored_tree = MerkleTree::from_leaves(leaves);

        assert_eq!(restored_tree.root_hash().unwrap(), &original_root);
        assert_eq!(restored_tree.size(), original_size);

        for i in 0..5 {
            let manifest_id = format!("id_{}", i);

            let original_proof = original_tree
                .generate_inclusion_proof(&manifest_id)
                .unwrap();

            let restored_proof = restored_tree
                .generate_inclusion_proof(&manifest_id)
                .unwrap();

            assert_eq!(original_proof.manifest_id, restored_proof.manifest_id);
            assert_eq!(original_proof.leaf_index, restored_proof.leaf_index);
            assert_eq!(original_proof.tree_size, restored_proof.tree_size);
            assert_eq!(original_proof.merkle_path, restored_proof.merkle_path);

            assert!(original_tree.verify_inclusion_proof(&restored_proof));
            assert!(restored_tree.verify_inclusion_proof(&original_proof));
        }
    }

    #[actix_web::test]
    async fn test_performance_comparison() {
        let sizes = vec![
            ("small", 1024),
            ("medium", 1024 * 1024),
            ("large", 10 * 1024 * 1024),
        ];

        for (name, size) in sizes {
            let data = vec![0u8; size];

            let start = std::time::Instant::now();
            let _standard_hash = atlas_common::hash::calculate_hash(&data);
            let standard_duration = start.elapsed();

            let start = std::time::Instant::now();
            let _optimized_hash = calculate_hash_optimized(&data, HashAlgorithm::Sha384);
            let optimized_duration = start.elapsed();

            let speedup =
                standard_duration.as_nanos() as f64 / optimized_duration.as_nanos() as f64;

            println!(
                "{} data ({}): standard {:?}, optimized {:?}, speedup: {:.2}x",
                name,
                if size >= 1024 * 1024 {
                    format!("{}MB", size / (1024 * 1024))
                } else {
                    format!("{}KB", size / 1024)
                },
                standard_duration,
                optimized_duration,
                speedup
            );
        }
    }
}
