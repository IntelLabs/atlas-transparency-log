use chrono::Utc;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use atlas_common::hash::{
    calculate_hash, calculate_hash_optimized, get_hardware_capabilities, BatchHasher, HashAlgorithm,
};
use atlas_transparency_log::merkle_tree::{LogLeaf, MerkleTree};

fn create_test_leaf(index: usize) -> LogLeaf {
    LogLeaf::new(
        format!("content_hash_{}", index),
        format!("manifest_{}", index),
        index as u64 + 1,
        Utc::now(),
    )
}

fn create_test_leaves(count: usize) -> Vec<LogLeaf> {
    (0..count).map(create_test_leaf).collect()
}

fn bench_hash_function_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_function_comparison");

    let sizes = vec![
        ("small", 1024),              // 1KB
        ("medium", 1024 * 1024),      // 1MB
        ("large", 10 * 1024 * 1024),  // 10MB
        ("xlarge", 50 * 1024 * 1024), // 50MB
    ];

    for (name, size) in sizes {
        let data = vec![0u8; size];
        group.throughput(Throughput::Bytes(size as u64));

        // Standard hash function
        group.bench_with_input(BenchmarkId::new("standard", name), &data, |b, data| {
            b.iter(|| black_box(calculate_hash(black_box(data))));
        });

        // Optimized hash function
        group.bench_with_input(BenchmarkId::new("optimized", name), &data, |b, data| {
            b.iter(|| {
                black_box(calculate_hash_optimized(
                    black_box(data),
                    HashAlgorithm::Sha384,
                ))
            });
        });
    }

    group.finish();
}

fn bench_merkle_tree_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_tree_operations");

    let sizes = vec![("small", 50), ("medium", 500), ("large", 2000)];

    for (name, size) in sizes {
        let leaves = create_test_leaves(size);
        group.throughput(Throughput::Elements(size as u64));

        // Tree building from leaves (optimized)
        group.bench_with_input(
            BenchmarkId::new("from_leaves", name),
            &leaves,
            |b, leaves| {
                b.iter(|| {
                    let tree = MerkleTree::from_leaves(black_box(leaves.clone()));
                    black_box(tree.root_hash().cloned())
                });
            },
        );

        // Individual leaf addition
        group.bench_with_input(
            BenchmarkId::new("individual_adds", name),
            &leaves,
            |b, leaves| {
                b.iter(|| {
                    let mut tree = MerkleTree::new();
                    for leaf in leaves {
                        tree.add_leaf(black_box(leaf.clone()));
                    }
                    black_box(tree.root_hash().cloned())
                });
            },
        );

        // Batch addition
        group.bench_with_input(
            BenchmarkId::new("batch_adds", name),
            &leaves,
            |b, leaves| {
                b.iter(|| {
                    let mut tree = MerkleTree::new();
                    tree.add_leaves(black_box(leaves.clone()));
                    black_box(tree.root_hash().cloned())
                });
            },
        );
    }

    group.finish();
}

fn bench_proof_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof_operations");

    let size = 1000;
    let leaves = create_test_leaves(size);
    let tree = MerkleTree::from_leaves(leaves);

    let middle_id = format!("manifest_{}", size / 2);

    group.throughput(Throughput::Elements(1));

    // Proof generation
    group.bench_function("proof_generation", |b| {
        b.iter(|| black_box(tree.generate_inclusion_proof(black_box(&middle_id))));
    });

    // Proof verification
    let proof = tree.generate_inclusion_proof(&middle_id).unwrap();
    group.bench_function("proof_verification", |b| {
        b.iter(|| black_box(tree.verify_inclusion_proof(black_box(&proof))));
    });

    // Consistency proof generation
    group.bench_function("consistency_proof_gen", |b| {
        b.iter(|| black_box(tree.generate_consistency_proof(black_box(500), black_box(1000))));
    });

    // Consistency proof verification
    let consistency_proof = tree.generate_consistency_proof(500, 1000).unwrap();
    group.bench_function("consistency_proof_verify", |b| {
        b.iter(|| black_box(tree.verify_consistency_proof(black_box(&consistency_proof))));
    });

    group.finish();
}

fn bench_batch_processing_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_processing_comparison");

    let batch_sizes = vec![
        ("small_batch", 10),
        ("medium_batch", 100),
        ("large_batch", 1000),
    ];

    for (name, count) in batch_sizes {
        let data_items: Vec<Vec<u8>> = (0..count)
            .map(|i| format!("test_data_{}", i).into_bytes())
            .collect();
        let data_refs: Vec<&[u8]> = data_items.iter().map(|v| v.as_slice()).collect();

        group.throughput(Throughput::Elements(count as u64));

        // Standard individual processing
        group.bench_with_input(
            BenchmarkId::new("individual_hashing", name),
            &data_refs,
            |b, data_refs| {
                b.iter(|| {
                    let results: Vec<String> = data_refs
                        .iter()
                        .map(|data| calculate_hash(black_box(data)))
                        .collect();
                    black_box(results)
                });
            },
        );

        // Optimized batch processing
        group.bench_with_input(
            BenchmarkId::new("batch_hashing", name),
            &data_refs,
            |b, data_refs| {
                b.iter(|| {
                    let batch_hasher = BatchHasher::new();
                    black_box(batch_hasher.hash_batch(black_box(data_refs), HashAlgorithm::Sha384))
                });
            },
        );

        // Optimized individual processing
        group.bench_with_input(
            BenchmarkId::new("optimized_individual", name),
            &data_refs,
            |b, data_refs| {
                b.iter(|| {
                    let results: Vec<String> = data_refs
                        .iter()
                        .map(|data| {
                            calculate_hash_optimized(black_box(data), HashAlgorithm::Sha384)
                        })
                        .collect();
                    black_box(results)
                });
            },
        );
    }

    group.finish();
}

fn bench_tree_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("tree_scaling");

    // Test how operations scale with tree size
    let sizes = vec![10, 50, 100, 500, 1000, 5000];

    for size in sizes {
        let leaves = create_test_leaves(size);
        let tree = MerkleTree::from_leaves(leaves.clone());

        group.throughput(Throughput::Elements(size as u64));

        // Time to build tree from scratch
        group.bench_with_input(
            BenchmarkId::new("build_from_scratch", size),
            &leaves,
            |b, leaves| {
                b.iter(|| {
                    let tree = MerkleTree::from_leaves(black_box(leaves.clone()));
                    black_box(tree.root_hash().cloned())
                });
            },
        );

        // Time to generate proof for middle element
        let middle_id = format!("manifest_{}", size / 2);
        group.bench_with_input(
            BenchmarkId::new("proof_generation", size),
            &(&tree, &middle_id),
            |b, (tree, id)| {
                b.iter(|| black_box(tree.generate_inclusion_proof(black_box(id))));
            },
        );

        // Time to verify proof
        let proof = tree.generate_inclusion_proof(&middle_id).unwrap();
        group.bench_with_input(
            BenchmarkId::new("proof_verification", size),
            &(&tree, &proof),
            |b, (tree, proof)| {
                b.iter(|| black_box(tree.verify_inclusion_proof(black_box(proof))));
            },
        );
    }

    group.finish();
}

fn bench_hardware_optimization(c: &mut Criterion) {
    let mut group = c.benchmark_group("hardware_optimization");

    // Display hardware capabilities
    let caps = get_hardware_capabilities();
    println!("\n=== Hardware Capabilities ===");
    println!("CPU cores: {}", caps.cpu_cores);
    println!("Intel SHA-NI: {}", caps.sha_extensions);
    println!("Intel AVX-512: {}", caps.avx512);
    println!("ARM crypto: {}", caps.arm_crypto);
    println!(
        "Optimal chunk size: {} MB",
        caps.optimal_chunk_size() / (1024 * 1024)
    );

    let sizes = vec![
        ("small", 10),
        ("medium", 100),
        ("large", 1000),
        ("xlarge", 10000),
    ];

    for (name, count) in sizes {
        let leaves = create_test_leaves(count);
        group.throughput(Throughput::Elements(count as u64));

        group.bench_with_input(
            BenchmarkId::new("optimized_build", name),
            &leaves,
            |b, leaves| {
                b.iter(|| {
                    let tree = MerkleTree::from_leaves(black_box(leaves.clone()));
                    black_box(tree.root_hash().cloned())
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    merkle_benches,
    bench_hash_function_comparison,
    bench_merkle_tree_operations,
    bench_proof_operations,
    bench_batch_processing_comparison,
    bench_tree_scaling,
    bench_hardware_optimization,
);

criterion_main!(merkle_benches);
