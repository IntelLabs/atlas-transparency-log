use actix_web::{http::header, web, App, HttpRequest, HttpResponse, HttpServer};
use atlas_common::hash::get_hardware_capabilities;
use atlas_transparency_log::{
    detect_content_type, hash_binary, is_valid_manifest_id,
    merkle_tree::{ConsistencyProof, InclusionProof, LogLeaf, MerkleProof, MerkleTree},
    sign_data, ContentFormat,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use log::{debug, error, info};
use mongodb::{Client, Database};
use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone)]
struct AppState {
    db: Arc<Database>,
    key_pair: Arc<Ed25519KeyPair>,
    merkle_tree: Arc<parking_lot::RwLock<MerkleTree>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ManifestEntry {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<mongodb::bson::oid::ObjectId>,
    pub manifest_id: String,
    pub manifest_type: String,
    pub content_format: ContentFormat,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_json: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_cbor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_binary: Option<String>,
    pub created_at: DateTime<Utc>,
    pub sequence_number: u64,
    pub hash: String,
    pub signature: String,
}

async fn store_manifest(
    state: web::Data<AppState>,
    req: HttpRequest,
    bytes: Bytes,
    path: web::Path<String>,
    query: web::Query<ManifestQuery>,
) -> HttpResponse {
    const MAX_MANIFEST_SIZE: usize = 10 * 1024 * 1024;
    if bytes.len() > MAX_MANIFEST_SIZE {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Manifest too large",
            "max_size": MAX_MANIFEST_SIZE
        }));
    }

    let manifest_id = path.to_string();
    if !is_valid_manifest_id(&manifest_id) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid manifest ID format",
            "details": "Must be a valid C2PA URN, UUID, or alphanumeric string"
        }));
    }

    let collection = state.db.collection::<ManifestEntry>("manifests");
    let manifest_type_param = &query.manifest_type;

    debug!(
        "Received manifest with ID: {}, manifest_type param: {:?}, size: {} bytes",
        &manifest_id,
        manifest_type_param,
        bytes.len()
    );

    let content_format = detect_content_type(&req);

    let start_time = std::time::Instant::now();
    let content_hash = hash_binary(&bytes);
    let hash_duration = start_time.elapsed();

    debug!(
        "Hash computed in {:?} using optimized hashing (size: {} bytes)",
        hash_duration,
        bytes.len()
    );

    let signature = sign_data(&state.key_pair, &content_hash.as_bytes());

    let sequence_count = collection.count_documents(None, None).await.unwrap_or(0);
    let sequence_number = sequence_count + 1;

    let now = Utc::now();

    let manifest_type = manifest_type_param
        .as_ref()
        .map(|s| s.clone())
        .unwrap_or_else(|| "unknown".to_string());

    let mut entry = ManifestEntry {
        id: None,
        manifest_id: manifest_id.clone(),
        manifest_type,
        content_format: content_format.clone(),
        manifest_json: None,
        manifest_cbor: None,
        manifest_binary: None,
        created_at: now,
        sequence_number: sequence_number as u64,
        hash: content_hash.clone(),
        signature,
    };

    match content_format {
        ContentFormat::JSON => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(json_value) => {
                let json_manifest_type = json_value
                    .get("manifest")
                    .and_then(|m| m.get("manifest_type"))
                    .or_else(|| json_value.get("manifest_type"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                if let Some(mt) = json_manifest_type {
                    if manifest_type_param.is_none() {
                        entry.manifest_type = mt;
                    }
                }

                debug!("Using manifest_type: {}", entry.manifest_type);
                entry.manifest_json = Some(json_value);
            }
            Err(e) => {
                error!("Failed to parse JSON: {:?}", e);
                return HttpResponse::BadRequest().body(format!("Invalid JSON format: {}", e));
            }
        },
        ContentFormat::CBOR => {
            let encoded = STANDARD.encode(&bytes);
            entry.manifest_cbor = Some(encoded);

            match serde_cbor::from_slice::<serde_json::Value>(&bytes) {
                Ok(cbor_value) => {
                    let cbor_manifest_type = cbor_value
                        .get("manifest_type")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());

                    if let Some(mt) = cbor_manifest_type {
                        if manifest_type_param.is_none() {
                            entry.manifest_type = mt;
                        }
                    } else if manifest_type_param.is_none() {
                        entry.manifest_type = "cbor_manifest".to_string();
                    }
                }
                Err(e) => {
                    debug!("Could not extract manifest_type from CBOR: {:?}", e);
                    if manifest_type_param.is_none() {
                        entry.manifest_type = "cbor_manifest".to_string();
                    }
                }
            }
        }
        ContentFormat::Binary => {
            let encoded = STANDARD.encode(&bytes);
            entry.manifest_binary = Some(encoded);

            if manifest_type_param.is_none() {
                entry.manifest_type = "binary_manifest".to_string();
            }
        }
    }

    match collection.insert_one(&entry, None).await {
        Ok(result) => {
            info!(
                "Successfully stored manifest with ID: {}",
                result.inserted_id
            );

            let leaf = LogLeaf::new(
                content_hash,
                manifest_id.clone(),
                sequence_number as u64,
                now,
            );

            let tree_start = std::time::Instant::now();
            {
                let mut tree = state.merkle_tree.write();
                tree.add_leaf(leaf);

                if let Err(e) = persist_merkle_tree(&state.db, &tree).await {
                    error!("Failed to persist Merkle tree: {:?}", e);
                }
            }
            let tree_duration = tree_start.elapsed();

            debug!(
                "Merkle tree updated in {:?} using optimized hashing",
                tree_duration
            );

            HttpResponse::Created().json(serde_json::json!({
                "id": result.inserted_id,
                "manifest_id": manifest_id,
                "sequence_number": sequence_number,
                "hash": entry.hash,
                "signature": entry.signature,
                "performance": {
                    "hash_duration_ms": hash_duration.as_millis(),
                    "tree_update_duration_ms": tree_duration.as_millis(),
                    "total_duration_ms": (hash_duration + tree_duration).as_millis()
                }
            }))
        }
        Err(e) => {
            error!("Failed to store manifest: {:?}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to store manifest",
                "details": e.to_string()
            }))
        }
    }
}

async fn persist_merkle_tree(
    db: &Database,
    tree: &MerkleTree,
) -> Result<(), mongodb::error::Error> {
    let collection = db.collection::<serde_json::Value>("merkle_tree_state");

    collection.delete_many(mongodb::bson::doc! {}, None).await?;

    let tree_state = serde_json::json!({
        "leaves": tree.leaves(),
        "tree_size": tree.size(),
        "root_hash": tree.root_hash(),
        "updated_at": Utc::now(),
        "hasher_algorithm": tree.hasher_algorithm().as_str(),
        "hardware_optimized": true,
    });

    collection.insert_one(tree_state, None).await?;
    Ok(())
}

async fn load_merkle_tree(db: &Database) -> MerkleTree {
    let collection = db.collection::<serde_json::Value>("merkle_tree_state");

    match collection.find_one(None, None).await {
        Ok(Some(state)) => {
            if let Ok(leaves) = serde_json::from_value::<Vec<LogLeaf>>(state["leaves"].clone()) {
                info!(
                    "Loading Merkle tree with {} leaves using optimized hashing",
                    leaves.len()
                );
                return MerkleTree::from_leaves(leaves);
            }
        }
        _ => {}
    }

    let manifests_collection = db.collection::<ManifestEntry>("manifests");
    if let Ok(cursor) = manifests_collection.find(None, None).await {
        if let Ok(manifests) = futures::stream::TryStreamExt::try_collect::<Vec<_>>(cursor).await {
            let mut tree = MerkleTree::new();

            info!(
                "Rebuilding Merkle tree from {} manifests using optimized batch processing",
                manifests.len()
            );

            let leaves: Vec<LogLeaf> = manifests
                .into_iter()
                .map(|manifest| {
                    LogLeaf::new(
                        manifest.hash,
                        manifest.manifest_id,
                        manifest.sequence_number,
                        manifest.created_at,
                    )
                })
                .collect();

            if leaves.len() > 10 {
                tree.add_leaves(leaves);
            } else {
                for leaf in leaves {
                    tree.add_leaf(leaf);
                }
            }

            return tree;
        }
    }

    MerkleTree::new()
}

async fn list_manifests(state: web::Data<AppState>, query: web::Query<ListQuery>) -> HttpResponse {
    let collection = state.db.collection::<ManifestEntry>("manifests");

    let limit = query.limit.unwrap_or(100) as i64;
    let skip = query.skip.unwrap_or(0) as u64;

    let mut filter = mongodb::bson::Document::new();

    if let Some(manifest_type) = &query.manifest_type {
        filter.insert("manifest_type", manifest_type);
    }

    if let Some(format) = &query.format {
        let content_format = match format.as_str() {
            "json" => "JSON",
            "cbor" => "CBOR",
            "binary" => "Binary",
            _ => "JSON",
        };
        filter.insert("content_format", content_format);
    }

    let find_options = mongodb::options::FindOptions::builder()
        .sort(mongodb::bson::doc! { "sequence_number": 1 })
        .skip(skip)
        .limit(limit)
        .build();

    let filter_doc = if filter.is_empty() {
        None
    } else {
        Some(filter)
    };

    match collection.find(filter_doc, find_options).await {
        Ok(cursor) => match futures::stream::TryStreamExt::try_collect::<Vec<_>>(cursor).await {
            Ok(manifests) => HttpResponse::Ok().json(manifests),
            Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
        },
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[derive(Debug, Deserialize)]
struct ManifestQuery {
    manifest_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListQuery {
    limit: Option<usize>,
    skip: Option<u64>,
    manifest_type: Option<String>,
    format: Option<String>,
}

async fn list_manifests_by_type(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<ListQuery>,
) -> HttpResponse {
    let manifest_type = path.into_inner();
    let collection = state.db.collection::<ManifestEntry>("manifests");

    let limit = query.limit.unwrap_or(100) as i64;
    let skip = query.skip.unwrap_or(0) as u64;

    let filter = mongodb::bson::doc! { "manifest_type": manifest_type };

    let find_options = mongodb::options::FindOptions::builder()
        .sort(mongodb::bson::doc! { "sequence_number": 1 })
        .skip(skip)
        .limit(limit)
        .build();

    match collection.find(filter, find_options).await {
        Ok(cursor) => match futures::stream::TryStreamExt::try_collect::<Vec<_>>(cursor).await {
            Ok(manifests) => HttpResponse::Ok().json(manifests),
            Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
        },
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

async fn get_manifest(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> HttpResponse {
    let collection = state.db.collection::<ManifestEntry>("manifests");
    debug!("Searching for manifest with ID: {}", &*path);

    match collection
        .find_one(mongodb::bson::doc! { "manifest_id": &*path }, None)
        .await
    {
        Ok(Some(manifest)) => {
            info!("Found manifest for ID: {}", &*path);

            let accept_cbor = req
                .headers()
                .get(header::ACCEPT)
                .and_then(|h| h.to_str().ok())
                .map(|s| s.contains("application/cbor"))
                .unwrap_or(false);

            match manifest.content_format {
                ContentFormat::CBOR if accept_cbor => {
                    if let Some(ref cbor_data) = manifest.manifest_cbor {
                        if let Ok(decoded) = STANDARD.decode(cbor_data) {
                            return HttpResponse::Ok()
                                .content_type("application/cbor")
                                .body(decoded);
                        }
                    }
                }
                ContentFormat::Binary => {
                    if let Some(ref binary_data) = manifest.manifest_binary {
                        if let Ok(decoded) = STANDARD.decode(binary_data) {
                            return HttpResponse::Ok()
                                .content_type("application/octet-stream")
                                .body(decoded);
                        }
                    }
                }
                _ => {}
            }

            HttpResponse::Ok().json(manifest)
        }
        Ok(None) => {
            debug!("No manifest found for ID: {}", &*path);
            HttpResponse::NotFound().body(format!("Manifest not found for ID: {}", &*path))
        }
        Err(e) => {
            error!("Error fetching manifest {}: {:?}", &*path, e);
            HttpResponse::InternalServerError().body(format!("Error fetching manifest: {}", e))
        }
    }
}

async fn get_inclusion_proof(state: web::Data<AppState>, path: web::Path<String>) -> HttpResponse {
    let manifest_id = path.into_inner();

    if !is_valid_manifest_id(&manifest_id) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid manifest ID format"
        }));
    }

    let tree = state.merkle_tree.read();
    match tree.generate_inclusion_proof(&manifest_id) {
        Some(proof) => HttpResponse::Ok().json(proof),
        None => HttpResponse::NotFound().json(serde_json::json!({
            "error": "No proof available",
            "manifest_id": manifest_id,
            "reason": "Manifest not found in tree"
        })),
    }
}

async fn get_merkle_root(state: web::Data<AppState>) -> HttpResponse {
    let tree = state.merkle_tree.read();
    match tree.root_hash() {
        Some(root) => HttpResponse::Ok().json(serde_json::json!({
            "root_hash": root,
            "tree_size": tree.size(),
            "hasher_algorithm": tree.hasher_algorithm().as_str(),
            "hardware_optimized": true
        })),
        None => HttpResponse::NotFound().body("No Merkle root available yet"),
    }
}

async fn verify_proof(
    state: web::Data<AppState>,
    proof: web::Json<InclusionProof>,
) -> HttpResponse {
    let tree = state.merkle_tree.read();
    let is_valid = tree.verify_inclusion_proof(&proof);

    HttpResponse::Ok().json(serde_json::json!({
        "valid": is_valid,
        "manifest_id": proof.manifest_id,
        "proof_description": (&*proof as &dyn MerkleProof).describe(),
        "verification_algorithm": tree.hasher_algorithm().as_str()
    }))
}

#[derive(Debug, Deserialize)]
struct ConsistencyProofRequest {
    old_size: usize,
    new_size: usize,
}

async fn get_consistency_proof(
    state: web::Data<AppState>,
    query: web::Query<ConsistencyProofRequest>,
) -> HttpResponse {
    let tree = state.merkle_tree.read();

    if query.old_size == 0 || query.new_size == 0 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Tree sizes must be greater than 0"
        }));
    }

    if query.old_size > query.new_size {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Old size must be less than or equal to new size"
        }));
    }

    match tree.generate_consistency_proof(query.old_size, query.new_size) {
        Some(proof) => HttpResponse::Ok().json(serde_json::json!({
            "proof": proof,
            "description": (&proof as &dyn MerkleProof).describe(),
            "hasher_algorithm": tree.hasher_algorithm().as_str()
        })),
        None => HttpResponse::NotFound().json(serde_json::json!({
            "error": "Cannot generate consistency proof",
            "old_size": query.old_size,
            "new_size": query.new_size,
            "current_tree_size": tree.size()
        })),
    }
}

async fn verify_consistency_proof(
    state: web::Data<AppState>,
    proof: web::Json<ConsistencyProof>,
) -> HttpResponse {
    let tree = state.merkle_tree.read();
    let is_valid = tree.verify_consistency_proof(&proof);

    HttpResponse::Ok().json(serde_json::json!({
        "valid": is_valid,
        "old_size": proof.old_size,
        "new_size": proof.new_size,
        "proof_elements": proof.proof_hashes.len(),
        "description": (&*proof as &dyn MerkleProof).describe(),
        "verification_algorithm": tree.hasher_algorithm().as_str()
    }))
}

async fn get_tree_stats(state: web::Data<AppState>) -> HttpResponse {
    let tree = state.merkle_tree.read();
    let caps = tree.get_hardware_capabilities();

    let total_leaves = tree.size();
    let has_root = tree.root_hash().is_some();

    let estimated_depth = if total_leaves > 0 {
        (total_leaves as f64).log2().ceil() as usize
    } else {
        0
    };

    HttpResponse::Ok().json(serde_json::json!({
        "current_size": total_leaves,
        "root_hash": tree.root_hash(),
        "estimated_depth": estimated_depth,
        "has_root": has_root,
        "timestamp": Utc::now(),
        "tree_health": if has_root { "healthy" } else { "empty" },
        "hasher_algorithm": tree.hasher_algorithm().as_str(),
        "hardware_optimization": {
            "enabled": true,
            "cpu_cores": caps.cpu_cores,
            "sha_extensions": caps.sha_extensions,
            "avx512": caps.avx512,
            "arm_crypto": caps.arm_crypto,
            "optimal_chunk_size_mb": caps.optimal_chunk_size() / (1024 * 1024)
        }
    }))
}

async fn get_historical_root(state: web::Data<AppState>, path: web::Path<usize>) -> HttpResponse {
    let tree_size = path.into_inner();
    let tree = state.merkle_tree.read();

    if tree_size == 0 || tree_size > tree.size() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid tree size",
            "requested_size": tree_size,
            "current_size": tree.size()
        }));
    }

    let root_hash = tree.compute_root_for_size(tree_size);

    match root_hash {
        Some(root) => HttpResponse::Ok().json(serde_json::json!({
            "tree_size": tree_size,
            "root_hash": root,
            "current_size": tree.size(),
            "hasher_algorithm": tree.hasher_algorithm().as_str()
        })),
        None => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to compute historical root"
        })),
    }
}

async fn get_hardware_info(_state: web::Data<AppState>) -> HttpResponse {
    let caps = get_hardware_capabilities();

    HttpResponse::Ok().json(serde_json::json!({
        "hardware_capabilities": {
            "cpu_cores": caps.cpu_cores,
            "intel_sha_ni": caps.sha_extensions,
            "intel_avx512": caps.avx512,
            "arm_crypto": caps.arm_crypto,
            "optimal_chunk_size_mb": caps.optimal_chunk_size() / (1024 * 1024)
        },
        "optimization_features": [
            "Intel SHA-NI extensions (3-5x faster on supported CPUs)",
            "AVX-512 parallel processing for large data (2-4x faster)",
            "ARM crypto extensions on Apple Silicon (2-3x faster)",
            "Multi-core parallel processing fallback",
            "Batch processing for Merkle tree operations"
        ],
        "performance_thresholds": {
            "large_data_threshold_mb": caps.optimal_chunk_size() / (1024 * 1024),
            "batch_processing_threshold": 4,
            "parallel_cores_threshold": 3
        }
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let mongodb_uri =
        std::env::var("MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".to_string());

    let server_host = std::env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let server_port = std::env::var("SERVER_PORT").unwrap_or_else(|_| "8080".to_string());

    let server_addr = format!("{}:{}", server_host, server_port);

    let key_path =
        std::env::var("KEY_PATH").unwrap_or_else(|_| "transparency_log_key.pem".to_string());
    let key_pair = match std::fs::read(&key_path) {
        Ok(pkcs8_bytes) => Ed25519KeyPair::from_pkcs8(&pkcs8_bytes).expect("Failed to parse key"),
        Err(_) => {
            let rng = ring::rand::SystemRandom::new();
            let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng).expect("Failed to generate key");
            std::fs::write(&key_path, pkcs8_bytes.as_ref()).expect("Failed to save key");
            Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())
                .expect("Failed to parse newly generated key")
        }
    };

    let client = Client::with_uri_str(&mongodb_uri)
        .await
        .expect("Failed to connect to MongoDB");

    let db_name = std::env::var("DB_NAME").unwrap_or_else(|_| "c2pa_manifests".to_string());

    let db = Arc::new(client.database(&db_name));

    let merkle_tree = Arc::new(parking_lot::RwLock::new(load_merkle_tree(&db).await));

    let caps = get_hardware_capabilities();
    info!(
        "Starting transparency log server with hardware optimization at http://{}:{}",
        if server_host == "0.0.0.0" {
            "localhost"
        } else {
            &server_host
        },
        server_port
    );

    info!(
        "Hardware capabilities - CPU cores: {}, SHA-NI: {}, AVX-512: {}, ARM crypto: {}",
        caps.cpu_cores, caps.sha_extensions, caps.avx512, caps.arm_crypto
    );

    if caps.sha_extensions {
        info!("Intel SHA-NI extensions enabled (3-5x faster hashing)");
    }
    if caps.avx512 {
        info!("Intel AVX-512 parallel processing enabled (2-4x faster for large data)");
    }
    if caps.arm_crypto {
        info!("ARM crypto extensions enabled (2-3x faster on Apple Silicon)");
    }
    if caps.cpu_cores >= 4 {
        info!(
            "Multi-core parallel processing enabled ({} cores)",
            caps.cpu_cores
        );
    }

    let state = web::Data::new(AppState {
        db: db.clone(),
        key_pair: Arc::new(key_pair),
        merkle_tree,
    });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .app_data(web::PayloadConfig::new(10 * 1024 * 1024))
            .route("/manifests", web::get().to(list_manifests))
            .route("/manifests/{id}", web::post().to(store_manifest))
            .route("/manifests/{id}", web::get().to(get_manifest))
            .route("/manifests/{id}/proof", web::get().to(get_inclusion_proof))
            .route("/merkle/root", web::get().to(get_merkle_root))
            .route("/merkle/verify", web::post().to(verify_proof))
            .route("/merkle/stats", web::get().to(get_tree_stats))
            .route("/merkle/consistency", web::get().to(get_consistency_proof))
            .route(
                "/merkle/consistency/verify",
                web::post().to(verify_consistency_proof),
            )
            .route("/merkle/root/{size}", web::get().to(get_historical_root))
            .route("/hardware", web::get().to(get_hardware_info))
            .route(
                "/types/{manifest_type}/manifests",
                web::get().to(list_manifests_by_type),
            )
    })
    .bind(&server_addr)?
    .run()
    .await
}

#[cfg(test)]
mod tests;
