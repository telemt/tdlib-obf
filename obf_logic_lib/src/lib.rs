use aes::Aes256;
use cbc::{cipher::{BlockDecryptMut, KeyIvInit}, Decryptor};
use digest::Digest;
use ecdsa::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use hmac::{Hmac, Mac};
use k256::elliptic_curve::rand_core::OsRng;
use k256::Secp256k1;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

type HmacSha256 = Hmac<Sha256>;

#[repr(C)]
pub struct DerivedKeys {
    pub aes_key: [u8; 32],
    pub mac_key: [u8; 32],
}

#[repr(C)]
pub struct BlobResult {
    pub data: *mut u8,
    pub len: usize,
    pub error: *const u8,
}

fn secure_zero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        *byte = 0;
    }
}

fn hmac_sha256(key: &[u8], message: &[u8], dest: &mut [u8; 32]) {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(message);
    let result = mac.finalize();
    dest.copy_from_slice(&result.into_bytes());
}

fn aes_cbc_decrypt(key: &[u8; 32], iv: &[u8], ciphertext: &[u8], plaintext: &mut [u8]) {
    type Aes256Cbc = cbc::cipher::BlockEncryptorLegacy<Aes256>;

    let cipher = Aes256Cbc::new(key.into(), iv.into());
    let mut block = PlaintextBuffer::new(plaintext);
    let blocks = ciphertext.chunks_exact(16);
    for chunk in blocks {
        let mut block_data = [0u8; 16];
        block_data.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block_data);
        block.push_block(&block_data);
    }
}

fn remove_pkcs7_padding(plaintext: &mut Vec<u8>) -> Result<(), &'static str> {
    if plaintext.is_empty() {
        return Err("Invalid plaintext block size");
    }
    if plaintext.len() % 16 != 0 {
        return Err("Invalid plaintext block size");
    }
    let padding = plaintext[plaintext.len() - 1] as usize;
    if padding == 0 || padding > 16 || padding > plaintext.len() {
        return Err("Invalid PKCS#7 padding");
    }
    for i in (plaintext.len() - padding)..plaintext.len() {
        if plaintext[i] != padding as u8 {
            return Err("Invalid PKCS#7 padding");
        }
    }
    plaintext.truncate(plaintext.len() - padding);
    Ok(())
}

struct PlaintextBuffer<'a> {
    data: &'a mut [u8],
    offset: usize,
}

impl<'a> PlaintextBuffer<'a> {
    fn new(data: &'a mut [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn push_block(&mut self, block: &[u8; 16]) {
        self.data[self.offset..self.offset + 16].copy_from_slice(block);
        self.offset += 16;
    }
}

pub fn derive_keys(key_material: &[u8]) -> DerivedKeys {
    let mut result = DerivedKeys {
        aes_key: [0u8; 32],
        mac_key: [0u8; 32],
    };

    let mut key_mat = key_material.to_vec();
    hmac_sha256(key_material, b"rsa_vault_v1_key", &mut result.aes_key);
    hmac_sha256(key_material, b"rsa_vault_v1_mac", &mut result.mac_key);
    secure_zero(&mut key_mat);

    result
}

pub fn reassemble_blob(left: &[u8], right: &[u8]) -> Result<Vec<u8>, &'static str> {
    if left.is_empty() || right.is_empty() {
        return Err("Unknown blob role");
    }
    if left.len() != right.len() {
        return Err("Shard size mismatch");
    }

    let mut blob = vec![0u8; left.len()];
    for i in 0..left.len() {
        blob[i] = left[i] ^ right[i];
    }
    Ok(blob)
}

pub fn decode_blob_impl(
    shard_a: &[u8],
    shard_b: &[u8],
    hash_index_seeds: &[u8],
    session_ticket_seeds: &[u8],
    packet_alignment_seeds: &[u8],
    config_cache_seeds: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let mut blob = reassemble_blob(shard_a, shard_b)?;

    if blob.len() < 48 || (blob.len() - 48) % 16 != 0 {
        return Err("Invalid blob size");
    }

    let ciphertext_size = blob.len() - 48;

    let mut key_material = Vec::new();
    key_material.reserve(hash_index_seeds.len() + session_ticket_seeds.len() +
                        packet_alignment_seeds.len() + config_cache_seeds.len());
    key_material.extend_from_slice(hash_index_seeds);
    key_material.extend_from_slice(session_ticket_seeds);
    key_material.extend_from_slice(packet_alignment_seeds);
    key_material.extend_from_slice(config_cache_seeds);

    let derived_keys = derive_keys(&key_material);
    secure_zero(&mut key_material);

    let mut mac_input = Vec::with_capacity(16 + ciphertext_size + 1);
    mac_input.extend_from_slice(&blob[..16 + ciphertext_size]);
    mac_input.push(0);

    let mut computed_mac = [0u8; 32];
    hmac_sha256(&derived_keys.mac_key, &mac_input, &mut computed_mac);
    secure_zero(&mut mac_input);

    if &computed_mac[..] != &blob[16 + ciphertext_size..16 + ciphertext_size + 32] {
        secure_zero(&mut computed_mac);
        secure_zero(&mut blob);
        return Err("Blob checksum mismatch");
    }
    secure_zero(&mut computed_mac);

    let mut plaintext = vec![0u8; ciphertext_size];
    let iv = &blob[..16];
    aes_cbc_decrypt(&derived_keys.aes_key, iv, &blob[16..16 + ciphertext_size], &mut plaintext);
    secure_zero(&mut blob);

    remove_pkcs7_padding(&mut plaintext)?;

    Ok(plaintext)
}

#[no_mangle]
pub extern "C" fn rust_derive_keys(
    hash_index_seeds: *const u8,
    hash_index_seeds_len: usize,
    session_ticket_seeds: *const u8,
    session_ticket_seeds_len: usize,
    packet_alignment_seeds: *const u8,
    packet_alignment_seeds_len: usize,
    config_cache_seeds: *const u8,
    config_cache_seeds_len: usize,
) -> DerivedKeys {
    unsafe {
        let hash_seeds = std::slice::from_raw_parts(hash_index_seeds, hash_index_seeds_len);
        let session_seeds = std::slice::from_raw_parts(session_ticket_seeds, session_ticket_seeds_len);
        let packet_seeds = std::slice::from_raw_parts(packet_alignment_seeds, packet_alignment_seeds_len);
        let config_seeds = std::slice::from_raw_parts(config_cache_seeds, config_cache_seeds_len);

        let mut key_material = Vec::new();
        key_material.reserve(hash_index_seeds_len + session_ticket_seeds_len +
                            packet_alignment_seeds_len + config_cache_seeds_len);
        key_material.extend_from_slice(hash_seeds);
        key_material.extend_from_slice(session_seeds);
        key_material.extend_from_slice(packet_seeds);
        key_material.extend_from_slice(config_seeds);

        let result = derive_keys(&key_material);
        secure_zero(&mut key_material);
        result
    }
}

#[no_mangle]
pub extern "C" fn rust_decode_blob(
    shard_a: *const u8,
    shard_a_len: usize,
    shard_b: *const u8,
    shard_b_len: usize,
    hash_index_seeds: *const u8,
    hash_index_seeds_len: usize,
    session_ticket_seeds: *const u8,
    session_ticket_seeds_len: usize,
    packet_alignment_seeds: *const u8,
    packet_alignment_seeds_len: usize,
    config_cache_seeds: *const u8,
    config_cache_seeds_len: usize,
) -> BlobResult {
    unsafe {
        let a = std::slice::from_raw_parts(shard_a, shard_a_len);
        let b = std::slice::from_raw_parts(shard_b, shard_b_len);
        let hash_seeds = std::slice::from_raw_parts(hash_index_seeds, hash_index_seeds_len);
        let session_seeds = std::slice::from_raw_parts(session_ticket_seeds, session_ticket_seeds_len);
        let packet_seeds = std::slice::from_raw_parts(packet_alignment_seeds, packet_alignment_seeds_len);
        let config_seeds = std::slice::from_raw_parts(config_cache_seeds, config_cache_seeds_len);

        match decode_blob_impl(a, b, hash_seeds, session_seeds, packet_seeds, config_seeds) {
            Ok(mut data) => {
                let ptr = data.as_ptr();
                let len = data.len();
                std::mem::forget(data);
                BlobResult {
                    data: ptr as *mut u8,
                    len,
                    error: std::ptr::null(),
                }
            }
            Err(e) => {
                BlobResult {
                    data: std::ptr::null_mut(),
                    len: 0,
                    error: e.as_ptr() as *const u8,
                }
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_free_blob(data: *mut u8, len: usize) {
    if !data.is_null() && len > 0 {
        unsafe {
            Vec::from_raw_parts(data, len, len);
        }
    }
}

pub fn check_window_entry_impl(
    fingerprint: u64,
    hash_index_seeds: &[u8],
    session_ticket_seeds: &[u8],
    packet_alignment_seeds: &[u8],
    config_cache_seeds: &[u8],
    route_window_primary: u64,
    route_window_secondary: u64,
) -> Result<(), &'static str> {
    let mut key_material = Vec::new();
    key_material.reserve(hash_index_seeds.len() + session_ticket_seeds.len() +
                        packet_alignment_seeds.len() + config_cache_seeds.len());
    key_material.extend_from_slice(hash_index_seeds);
    key_material.extend_from_slice(session_ticket_seeds);
    key_material.extend_from_slice(packet_alignment_seeds);
    key_material.extend_from_slice(config_cache_seeds);

    let mut mask = [0u8; 32];
    hmac_sha256(b"table_mix_v1_delta", &key_material, &mut mask);
    secure_zero(&mut key_material);

    let expected_main = route_window_primary ^ u64::from_le_bytes([mask[0], mask[1], mask[2], mask[3], mask[4], mask[5], mask[6], mask[7]]);
    let expected_test = route_window_secondary ^ u64::from_le_bytes([mask[8], mask[9], mask[10], mask[11], mask[12], mask[13], mask[14], mask[15]]);

    if fingerprint == expected_main || fingerprint == expected_test {
        Ok(())
    } else {
        Err("Unexpected window entry")
    }
}

#[no_mangle]
pub extern "C" fn rust_check_window_entry(
    fingerprint: u64,
    hash_index_seeds: *const u8,
    hash_index_seeds_len: usize,
    session_ticket_seeds: *const u8,
    session_ticket_seeds_len: usize,
    packet_alignment_seeds: *const u8,
    packet_alignment_seeds_len: usize,
    config_cache_seeds: *const u8,
    config_cache_seeds_len: usize,
    route_window_primary: u64,
    route_window_secondary: u64,
) -> i32 {
    unsafe {
        let hash_seeds = std::slice::from_raw_parts(hash_index_seeds, hash_index_seeds_len);
        let session_seeds = std::slice::from_raw_parts(session_ticket_seeds, session_ticket_seeds_len);
        let packet_seeds = std::slice::from_raw_parts(packet_alignment_seeds, packet_alignment_seeds_len);
        let config_seeds = std::slice::from_raw_parts(config_cache_seeds, config_cache_seeds_len);

        match check_window_entry_impl(fingerprint, hash_seeds, session_seeds, packet_seeds, config_seeds, route_window_primary, route_window_secondary) {
            Ok(()) => 0,
            Err(_) => 1,
        }
    }
}

pub fn table_mix_theta(
    input_data: &[u8],
    hash_index_seeds: &[u8],
    session_ticket_seeds: &[u8],
    packet_alignment_seeds: &[u8],
    config_cache_seeds: &[u8],
) -> [u8; 32] {
    let mut key_material = Vec::new();
    key_material.reserve(hash_index_seeds.len() + session_ticket_seeds.len() +
                        packet_alignment_seeds.len() + config_cache_seeds.len());
    key_material.extend_from_slice(hash_index_seeds);
    key_material.extend_from_slice(session_ticket_seeds);
    key_material.extend_from_slice(packet_alignment_seeds);
    key_material.extend_from_slice(config_cache_seeds);

    let mut result = [0u8; 32];
    hmac_sha256(b"table_mix_v1_theta", &key_material, &mut result);
    secure_zero(&mut key_material);
    result
}

pub const STEALTH_MIN_ENCRYPTED_SIZE: usize = 128;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use digest::Digest;
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha256_digest(data: &[u8], output: &mut [u8]) {
    let hash = sha256(data);
    output.copy_from_slice(&hash);
}

pub fn init_grease_values(seed: &[u8]) -> Vec<u8> {
    let mut grease_values = vec![0u8; seed.len()];
    for i in 0..grease_values.len() {
        let val = seed[i];
        let adjusted = (val & 0xF0) | 0x0A;
        grease_values[i] = adjusted;
    }
    for i in 1..grease_values.len() {
        if i % 2 == 0 && grease_values[i] == grease_values[i - 1] {
            grease_values[i] ^= 0x10;
        }
    }
    grease_values
}

pub fn generate_x25519_public_key(seed: &[u8; 32]) -> [u8; 32] {
    let mut secret_bytes = *seed;
    secret_bytes[31] &= 127;
    
    let secret = x25519_dalek::StaticSecret::from(secret_bytes);
    let public = x25519_dalek::PublicKey::from(&secret);
    public.as_bytes().clone()
}

pub fn generate_secp256r1_public_key(seed: &[u8; 32]) -> [u8; 65] {
    let mut seed_arr = *seed;
    let signing_key = k256::ecdsa::SigningKey::from_bytes(&seed_arr.into()).expect("valid key");
    let verifying_key = signing_key.verifying_key();
    let encoded = verifying_key.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    let mut result = [0u8; 65];
    result[..bytes.len()].copy_from_slice(bytes);
    result
}

pub fn hmac_sha256_finalize(secret: &[u8], data: &[u8], dest: &mut [u8; 32], unix_time: i32) {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(data);
    let result: [u8; 32] = mac.finalize().into();
    
    let old = u32::from_le_bytes([result[28], result[29], result[30], result[31]]);
    let masked = old ^ (unix_time as u32);
    
    dest.copy_from_slice(&result[..28]);
    dest[28] = (masked & 0xff) as u8;
    dest[29] = ((masked >> 8) & 0xff) as u8;
    dest[30] = ((masked >> 16) & 0xff) as u8;
    dest[31] = ((masked >> 24) & 0xff) as u8;
}

pub fn calc_stealth_padding(
    data_size: usize,
    enc_size: usize,
    raw_size: usize,
    min_padding: usize,
    max_padding: usize,
) -> usize {
    let mut encrypted_size = enc_size + data_size;
    if min_padding > 0 {
        encrypted_size = encrypted_size.saturating_add(min_padding);
    }
    let aligned = (encrypted_size + 15) & !15;
    let aligned = aligned.max(128);
    raw_size + aligned
}

#[no_mangle]
pub extern "C" fn rust_calc_stealth_size(
    data_size: usize,
    enc_header_size: usize,
    raw_header_size: usize,
    min_padding: usize,
    max_padding: usize,
) -> usize {
    calc_stealth_padding(data_size, enc_header_size, raw_header_size, min_padding, max_padding)
}

#[no_mangle]
pub extern "C" fn rust_sha256(data: *const u8, len: usize) -> *mut [u8; 32] {
    unsafe {
        let slice = std::slice::from_raw_parts(data, len);
        let result = Box::new(sha256(slice));
        Box::into_raw(result)
    }
}

#[no_mangle]
pub extern "C" fn rust_sha256_free(hash: *mut [u8; 32]) {
    if !hash.is_null() {
        unsafe { Box::from_raw(hash) };
    }
}

#[no_mangle]
pub extern "C" fn rust_generate_x25519_public_key(seed: *const u8) -> *mut [u8; 32] {
    unsafe {
        let seed_arr = std::slice::from_raw_parts(seed, 32);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(seed_arr);
        let result = Box::new(generate_x25519_public_key(&arr));
        Box::into_raw(result)
    }
}

#[no_mangle]
pub extern "C" fn rust_generate_secp256r1_public_key(seed: *const u8) -> *mut [u8; 65] {
    unsafe {
        let seed_arr = std::slice::from_raw_parts(seed, 32);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(seed_arr);
        let result = Box::new(generate_secp256r1_public_key(&arr));
        Box::into_raw(result)
    }
}

#[no_mangle]
pub extern "C" fn rust_hmac_sha256_finalize(
    secret: *const u8,
    data: *const u8,
    data_len: usize,
    unix_time: i32,
    dest: *mut u8,
) {
    unsafe {
        let secret_slice = std::slice::from_raw_parts(secret, 16);
        let data_slice = std::slice::from_raw_parts(data, data_len);
        let dest_slice = std::slice::from_raw_parts_mut(dest, 32);
        let mut result = [0u8; 32];
        hmac_sha256_finalize(secret_slice, data_slice, &mut result, unix_time);
        dest_slice.copy_from_slice(&result);
    }
}

#[no_mangle]
pub extern "C" fn rust_init_grease_values(seed: *const u8, seed_len: usize) -> *mut Vec<u8> {
    unsafe {
        let seed_slice = std::slice::from_raw_parts(seed, seed_len);
        let result = Box::new(init_grease_values(seed_slice));
        Box::into_raw(result)
    }
}

#[no_mangle]
pub extern "C" fn rust_grease_values_free(vec: *mut Vec<u8>) {
    if !vec.is_null() {
        unsafe { Box::from_raw(vec) };
    }
}

// ============================================================================
// ClientHelloExecutor - Full TLS ClientHello Generation
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ClientHelloOpType {
    Bytes,
    RandomBytes,
    ZeroBytes,
    Domain,
    GreaseValue,
    X25519KeyShareEntry,
    Secp256r1KeyShareEntry,
    X25519MlKem768KeyShareEntry,
    GreaseKeyShareEntry,
    X25519PublicKey,
    Scope16Begin,
    Scope16End,
    Permutation,
    PaddingToTarget,
}

#[derive(Clone)]
pub struct ClientHelloOp {
    pub op_type: ClientHelloOpType,
    pub length: usize,
    pub value: i32,
    pub data: Vec<u8>,
    pub permutation_parts: Vec<Vec<ClientHelloOp>>,
}

impl ClientHelloOp {
    pub fn bytes(data: &[u8]) -> Self {
        Self { op_type: ClientHelloOpType::Bytes, length: 0, value: 0, data: data.to_vec(), permutation_parts: vec![] }
    }
    pub fn random_bytes(len: usize) -> Self {
        Self { op_type: ClientHelloOpType::RandomBytes, length: len, value: 0, data: vec![], permutation_parts: vec![] }
    }
    pub fn zero_bytes(len: usize) -> Self {
        Self { op_type: ClientHelloOpType::ZeroBytes, length: len, value: 0, data: vec![], permutation_parts: vec![] }
    }
    pub fn domain() -> Self {
        Self { op_type: ClientHelloOpType::Domain, length: 0, value: 0, data: vec![], permutation_parts: vec![] }
    }
    pub fn grease(value: i32) -> Self {
        Self { op_type: ClientHelloOpType::GreaseValue, length: 0, value, data: vec![], permutation_parts: vec![] }
    }
    pub fn x25519_key_share_entry() -> Self {
        Self { op_type: ClientHelloOpType::X25519KeyShareEntry, length: 0, value: 0, data: vec![], permutation_parts: vec![] }
    }
    pub fn secp256r1_key_share_entry() -> Self {
        Self { op_type: ClientHelloOpType::Secp256r1KeyShareEntry, length: 0, value: 0, data: vec![], permutation_parts: vec![] }
    }
    pub fn x25519_ml_kem_768_key_share_entry() -> Self {
        Self { op_type: ClientHelloOpType::X25519MlKem768KeyShareEntry, length: 0, value: 0, data: vec![], permutation_parts: vec![] }
    }
    pub fn grease_key_share_entry(value: i32) -> Self {
        Self { op_type: ClientHelloOpType::GreaseKeyShareEntry, length: 0, value, data: vec![], permutation_parts: vec![] }
    }
    pub fn x25519_public_key() -> Self {
        Self { op_type: ClientHelloOpType::X25519PublicKey, length: 0, value: 0, data: vec![], permutation_parts: vec![] }
    }
    pub fn scope16_begin() -> Self {
        Self { op_type: ClientHelloOpType::Scope16Begin, length: 0, value: 0, data: vec![], permutation_parts: vec![] }
    }
    pub fn scope16_end() -> Self {
        Self { op_type: ClientHelloOpType::Scope16End, length: 0, value: 0, data: vec![], permutation_parts: vec![] }
    }
    pub fn permutation(parts: Vec<Vec<ClientHelloOp>>) -> Self {
        Self { op_type: ClientHelloOpType::Permutation, length: 0, value: 0, data: vec![], permutation_parts: parts }
    }
    pub fn padding_to_target(value: i32) -> Self {
        Self { op_type: ClientHelloOpType::PaddingToTarget, length: 0, value, data: vec![], permutation_parts: vec![] }
    }
}

#[repr(C)]
pub struct ExecutorConfig {
    pub grease_value_count: usize,
    pub has_ech: bool,
    pub ech_outer_type: u8,
    pub ech_kdf_id: u16,
    pub ech_aead_id: u16,
    pub ech_payload_length: i32,
    pub ech_enc_key_length: i32,
    pub alps_type: u16,
    pub padding_target_entropy: i32,
    pub pq_group_id_override: u16,
    pub padding_extension_payload_length_override: usize,
    pub force_http11_only_alpn: bool,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            grease_value_count: 7,
            has_ech: false,
            ech_outer_type: 0,
            ech_kdf_id: 0x0001,
            ech_aead_id: 0x0001,
            ech_payload_length: 144,
            ech_enc_key_length: 32,
            alps_type: 0,
            padding_target_entropy: 0,
            pq_group_id_override: 0x11EC,
            padding_extension_payload_length_override: 0,
            force_http11_only_alpn: false,
        }
    }
}

pub struct ExecutionContext {
    grease_values: Vec<u8>,
    domain: Vec<u8>,
    config: ExecutorConfig,
    rng: Vec<u8>,
    rng_pos: usize,
}

impl ExecutionContext {
    pub fn new(config: ExecutorConfig, domain: &[u8], mut rng_seed: Vec<u8>) -> Self {
        let grease_values = init_grease_values(&rng_seed);
        let domain = domain.iter().take(256).cloned().collect();
        rng_seed.push(0);
        Self { grease_values, domain, config, rng: rng_seed, rng_pos: 0 }
    }
    
    pub fn grease(&self, index: usize) -> u8 {
        self.grease_values.get(index).copied().unwrap_or(0)
    }
    
    pub fn domain(&self) -> &[u8] {
        &self.domain
    }
    
    pub fn config(&self) -> ExecutorConfig {
        self.config
    }
    
    pub fn rng_fill(&mut self, dest: &mut [u8]) {
        for byte in dest.iter_mut() {
            if self.rng_pos >= self.rng.len() {
                self.rng = sha256(&self.rng);
                self.rng_pos = 0;
            }
            *byte = self.rng[self.rng_pos];
            self.rng_pos += 1;
        }
    }
}

fn rng_shuffle<T: Clone>(items: &mut [T], rng: &mut Vec<u8>) {
    let len = items.len();
    if len <= 1 { return; }
    let mut i = len;
    while i > 1 {
        let j = (rng[i - 1] as usize) % i;
        if j != i - 1 {
            items.swap(i - 1, j);
        }
        i -= 1;
        rng.fill(0);
        let new_hash = sha256(rng);
        rng.copy_from_slice(&new_hash);
    }
}

pub struct LengthCalculator {
    size: usize,
    scope_offsets: Vec<usize>,
}

impl LengthCalculator {
    pub fn new() -> Self { Self { size: 0, scope_offsets: vec![] } }
    
    pub fn append(&mut self, op: &ClientHelloOp, ctx: &ExecutionContext) {
        match op.op_type {
            ClientHelloOpType::Bytes => self.size += op.data.len(),
            ClientHelloOpType::RandomBytes | ClientHelloOpType::ZeroBytes => self.size += op.length,
            ClientHelloOpType::Domain => self.size += ctx.domain().len(),
            ClientHelloOpType::GreaseValue => self.size += 2,
            ClientHelloOpType::X25519KeyShareEntry => self.size += 36,
            ClientHelloOpType::Secp256r1KeyShareEntry => self.size += 69,
            ClientHelloOpType::X25519MlKem768KeyShareEntry => self.size += 1218,
            ClientHelloOpType::GreaseKeyShareEntry => self.size += 5,
            ClientHelloOpType::X25519PublicKey => self.size += 32,
            ClientHelloOpType::Scope16Begin => {
                self.size += 2;
                self.scope_offsets.push(self.size);
            }
            ClientHelloOpType::Scope16End => { self.scope_offsets.pop(); }
            ClientHelloOpType::Permutation => {
                let mut parts = op.permutation_parts.clone();
                rng_shuffle(&mut parts, &mut ctx.rng.clone());
                for part in &parts {
                    for sub_op in part {
                        self.append(sub_op, ctx);
                    }
                }
            }
            ClientHelloOpType::PaddingToTarget => {
                let override_len = ctx.config().padding_extension_payload_length_override;
                if override_len > 0 {
                    self.size += 4 + override_len;
                } else if !ctx.config().has_ech {
                    let target = op.value as usize + ctx.config().padding_target_entropy as usize;
                    if self.size < target {
                        self.size = target + 4;
                    }
                }
            }
        }
    }
    
    pub fn finish(&self) -> Result<usize, &'static str> {
        if !self.scope_offsets.is_empty() { return Err("Unbalanced scopes"); }
        Ok(self.size)
    }
}

pub struct ByteWriter {
    all: Vec<u8>,
    remaining: Vec<u8>,
    offset: usize,
    scope_offsets: Vec<usize>,
    rng: Vec<u8>,
    rng_pos: usize,
}

impl ByteWriter {
    pub fn new(size: usize) -> Self {
        let mut all = vec![0u8; size];
        Self { all: all.clone(), remaining: all, offset: 0, scope_offsets: vec![], rng: vec![0u8; 32], rng_pos: 0 }
    }
    
    pub fn remaining(&self) -> usize { self.remaining.len() }
    
    fn rng_next(&mut self) -> u8 {
        if self.rng_pos >= 32 {
            self.rng = sha256(&self.rng);
            self.rng_pos = 0;
        }
        let b = self.rng[self.rng_pos];
        self.rng_pos += 1;
        b
    }
    
    pub fn append(&mut self, op: &ClientHelloOp, ctx: &ExecutionContext) {
        match op.op_type {
            ClientHelloOpType::Bytes => {
                self.remaining[..op.data.len()].copy_from_slice(&op.data);
                self.remaining = self.remaining[op.data.len()..].to_vec();
            }
            ClientHelloOpType::RandomBytes => {
                for byte in self.remaining[..op.length].iter_mut() {
                    *byte = self.rng_next();
                }
                self.remaining = self.remaining[op.length..].to_vec();
            }
            ClientHelloOpType::ZeroBytes => {
                for byte in self.remaining[..op.length].iter_mut() {
                    *byte = 0;
                }
                self.remaining = self.remaining[op.length..].to_vec();
            }
            ClientHelloOpType::Domain => {
                let d = ctx.domain();
                self.remaining[..d.len()].copy_from_slice(d);
                self.remaining = self.remaining[d.len()..].to_vec();
            }
            ClientHelloOpType::GreaseValue => {
                let g = ctx.grease(op.value as usize);
                self.remaining[0] = g;
                self.remaining[1] = g;
                self.remaining = self.remaining[2..].to_vec();
            }
            ClientHelloOpType::X25519KeyShareEntry => {
                self.remaining[..2].copy_from_slice(&[0x00, 0x1d]);
                self.remaining[2] = 0x00;
                self.remaining[3] = 0x20;
                self.remaining = self.remaining[4..].to_vec();
                self.gen_x25519_keyshare();
            }
            ClientHelloOpType::Secp256r1KeyShareEntry => {
                self.remaining[..2].copy_from_slice(&[0x00, 0x17]);
                self.remaining[2] = 0x00;
                self.remaining[3] = 0x41;
                self.remaining = self.remaining[4..].to_vec();
                self.gen_secp256r1_keyshare();
            }
            ClientHelloOpType::X25519MlKem768KeyShareEntry => {
                let pq = ctx.config().pq_group_id_override;
                self.remaining[0] = (pq >> 8) as u8;
                self.remaining[1] = pq as u8;
                self.remaining[2] = 0x04;
                self.remaining[3] = 0xc0;
                self.remaining = self.remaining[4..].to_vec();
                self.gen_mlkem_keyshare();
                self.gen_x25519_keyshare();
            }
            ClientHelloOpType::GreaseKeyShareEntry => {
                let g = ctx.grease(op.value as usize);
                self.remaining[0] = g;
                self.remaining[1] = g;
                self.remaining[2] = 0x00;
                self.remaining[3] = 0x01;
                self.remaining[4] = 0x00;
                self.remaining = self.remaining[5..].to_vec();
            }
            ClientHelloOpType::X25519PublicKey => self.gen_x25519_keyshare(),
            ClientHelloOpType::Scope16Begin => {
                self.scope_offsets.push(self.offset);
                self.remaining = self.remaining[2..].to_vec();
                self.offset += 2;
            }
            ClientHelloOpType::Scope16End => {
                let begin = self.scope_offsets.pop().unwrap();
                let size = self.offset - begin - 2;
                self.all[begin] = (size >> 8) as u8;
                self.all[begin + 1] = size as u8;
            }
            ClientHelloOpType::Permutation => {
                let mut parts = op.permutation_parts.clone();
                rng_shuffle(&mut parts, &mut self.rng);
                for part in &parts {
                    for sub_op in part {
                        self.append(sub_op, ctx);
                    }
                }
            }
            ClientHelloOpType::PaddingToTarget => {
                let override_len = ctx.config().padding_extension_payload_length_override;
                if override_len > 0 {
                    self.remaining[..2].copy_from_slice(&[0x00, 0x15]);
                    self.remaining[2] = 0x00;
                    self.remaining[3] = override_len as u8;
                    self.remaining = self.remaining[4..].to_vec();
                    for byte in self.remaining[..override_len].iter_mut() { *byte = 0; }
                    self.remaining = self.remaining[override_len..].to_vec();
                } else if !ctx.config().has_ech {
                    let target = op.value as usize + ctx.config().padding_target_entropy as usize;
                    let need = target.saturating_sub(self.offset);
                    if need > 0 {
                        self.remaining[..2].copy_from_slice(&[0x00, 0x15]);
                        self.remaining[2] = 0x00;
                        self.remaining[3] = need as u8;
                        self.remaining = self.remaining[4..].to_vec();
                        for byte in self.remaining[..need].iter_mut() { *byte = 0; }
                        self.remaining = self.remaining[need..].to_vec();
                    }
                }
            }
        }
    }
    
    fn gen_x25519_keyshare(&mut self) {
        let mut seed = [0u8; 32];
        for b in seed.iter_mut() { *b = self.rng_next(); }
        seed[31] &= 127;
        let key = generate_x25519_public_key(&seed);
        self.remaining[..32].copy_from_slice(&key);
        self.remaining = self.remaining[32..].to_vec();
    }
    
    fn gen_secp256r1_keyshare(&mut self) {
        let mut seed = [0u8; 32];
        for b in seed.iter_mut() { *b = self.rng_next(); }
        let key = generate_secp256r1_public_key(&seed);
        self.remaining[..65].copy_from_slice(&key);
        self.remaining = self.remaining[65..].to_vec();
    }
    
    fn gen_mlkem_keyshare(&mut self) {
        for i in 0..384 {
            let a = (self.rng_next() as usize) % 3329;
            let b = (self.rng_next() as usize) % 3329;
            self.remaining[i * 3] = a as u8;
            self.remaining[i * 3 + 1] = ((a >> 8) + ((b & 15) << 4)) as u8;
            self.remaining[i * 3 + 2] = (b >> 4) as u8;
        }
        for i in 1152..1184 {
            self.remaining[i] = self.rng_next();
        }
        self.remaining = self.remaining[1216..].to_vec();
    }
    
    pub fn finalize(&mut self, secret: &[u8], unix_time: i32) {
        let hash_dest = &mut self.all[11..43];
        hmac_sha256(secret, &self.all, hash_dest);
        let old = u32::from_le_bytes([hash_dest[28], hash_dest[29], hash_dest[30], hash_dest[31]]);
        let masked = old ^ (unix_time as u32);
        hash_dest[28..32].copy_from_slice(&masked.to_le_bytes());
    }
    
    pub fn into_inner(self) -> Vec<u8> { self.all }
}

pub fn client_hello_execute(
    ops: &[ClientHelloOp],
    domain: &[u8],
    secret: &[u8],
    unix_time: i32,
    config: ExecutorConfig,
    rng_seed: Vec<u8>,
) -> Result<Vec<u8>, &'static str> {
    assert!(secret.len() == 16);
    assert!(!domain.is_empty());
    
    let mut ctx = ExecutionContext::new(config, domain, rng_seed);
    
    let mut calc = LengthCalculator::new();
    for op in ops {
        calc.append(op, &ctx);
    }
    let length = calc.finish()?;
    
    let mut writer = ByteWriter::new(length);
    for op in ops {
        writer.append(op, &ctx);
    }
    if writer.remaining() != 0 {
        return Err("ByteWriter size mismatch");
    }
    writer.finalize(secret, unix_time);
    Ok(writer.into_inner())
}

// ============================================================================
// FFI Exports for ClientHelloExecutor
// ============================================================================

#[no_mangle]
pub extern "C" fn rust_client_hello_execute(
    domain: *const u8,
    domain_len: usize,
    secret: *const u8,
    unix_time: i32,
    config: ExecutorConfig,
    rng_seed: *const u8,
    rng_seed_len: usize,
    result_len: *mut usize,
) -> *mut u8 {
    unsafe {
        let domain_slice = std::slice::from_raw_parts(domain, domain_len);
        let secret_slice = std::slice::from_raw_parts(secret, 16);
        let rng_vec = std::slice::from_raw_parts(rng_seed, rng_seed_len).to_vec();
        let mut ops: Vec<ClientHelloOp> = vec![];
        
        match client_hello_execute(&ops, domain_slice, secret_slice, unix_time, config, rng_vec) {
            Ok(data) => {
                *result_len = data.len();
                let ptr = data.as_ptr();
                std::mem::forget(data);
                ptr as *mut u8
            }
            Err(_) => std::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub extern "C" fn rust_client_hello_free(data: *mut u8, len: usize) {
    if !data.is_null() && len > 0 {
        unsafe { Vec::from_raw_parts(data, len, len) };
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_keys() {
        let key_material = b"test_key_material";
        let keys = derive_keys(key_material);
        assert_ne!(keys.aes_key, keys.mac_key);
    }

    #[test]
    fn test_reassemble_blob() {
        let left = vec![0x01, 0x02, 0x03, 0x04];
        let right = vec![0xFF, 0xFE, 0xFD, 0xFC];
        let result = reassemble_blob(&left, &right).unwrap();
        assert_eq!(result, vec![0xFE, 0xFC, 0xFE, 0xF8]);
    }

    #[test]
    fn test_stealth_padding() {
        let size = calc_stealth_padding(100, 4, 12, 0, 0);
        assert!(size >= 128 + 12);
    }
    
    #[test]
    fn test_client_hello_op() {
        let op = ClientHelloOp::bytes(b"\x16\x03\x01");
        assert_eq!(op.op_type, ClientHelloOpType::Bytes);
    }
}
