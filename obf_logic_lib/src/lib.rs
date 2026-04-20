use aes::Aes256;
use cbc::{cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit}, Decryptor};
use hmac::{Hmac, Mac};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use sha2::Sha256;
use std::os::raw::c_char;
use subtle::ConstantTimeEq;

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
    pub error: *const c_char,
}

unsafe fn ffi_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts(ptr, len))
}

unsafe fn ffi_slice_mut<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 {
        return Some(&mut []);
    }
    if ptr.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts_mut(ptr, len))
}

fn ffi_error_ptr(error: &'static str) -> *const c_char {
    match error {
        "Unknown blob role" => b"Unknown blob role\0".as_ptr() as *const c_char,
        "Shard size mismatch" => b"Shard size mismatch\0".as_ptr() as *const c_char,
        "Invalid blob size" => b"Invalid blob size\0".as_ptr() as *const c_char,
        "Blob checksum mismatch" => b"Blob checksum mismatch\0".as_ptr() as *const c_char,
        "Invalid plaintext block size" => b"Invalid plaintext block size\0".as_ptr() as *const c_char,
        "Invalid PKCS#7 padding" => b"Invalid PKCS#7 padding\0".as_ptr() as *const c_char,
        "Invalid IV size" => b"Invalid IV size\0".as_ptr() as *const c_char,
        "Invalid ciphertext block layout" => b"Invalid ciphertext block layout\0".as_ptr() as *const c_char,
        _ => b"Internal error\0".as_ptr() as *const c_char,
    }
}

fn secure_zero(data: &mut [u8]) {
    // Use volatile writes to prevent dead-store elimination by the optimizer.
    for (i, byte) in data.iter_mut().enumerate() {
        unsafe { std::ptr::write_volatile(byte as *mut u8, 0u8); }
        let _ = i; // suppress unused-variable warning
    }
}

fn hmac_sha256(key: &[u8], message: &[u8], dest: &mut [u8; 32]) {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(message);
    let result = mac.finalize();
    dest.copy_from_slice(&result.into_bytes());
}

fn aes_cbc_decrypt(
    key: &[u8; 32],
    iv: &[u8],
    ciphertext: &[u8],
    plaintext: &mut [u8],
) -> Result<(), &'static str> {
    let iv: &[u8; 16] = iv.try_into().map_err(|_| "Invalid IV size")?;
    let cipher = Decryptor::<Aes256>::new(key.into(), iv.into());
    cipher
        .decrypt_padded_b2b_mut::<NoPadding>(ciphertext, plaintext)
        .map_err(|_| "Invalid ciphertext block layout")?;
    Ok(())
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

    // Constant-time comparison: prevents timing oracle that would allow MAC forgery bit-by-bit.
    let stored_mac = &blob[16 + ciphertext_size..16 + ciphertext_size + 32];
    let mac_match = computed_mac.ct_eq(stored_mac);
    if mac_match.unwrap_u8() == 0 {
        secure_zero(&mut computed_mac);
        secure_zero(&mut blob);
        return Err("Blob checksum mismatch");
    }
    secure_zero(&mut computed_mac);

    let mut plaintext = vec![0u8; ciphertext_size];
    let iv = &blob[..16];
    aes_cbc_decrypt(&derived_keys.aes_key, iv, &blob[16..16 + ciphertext_size], &mut plaintext)?;
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
        let Some(hash_seeds) = ffi_slice(hash_index_seeds, hash_index_seeds_len) else {
            return DerivedKeys { aes_key: [0u8; 32], mac_key: [0u8; 32] };
        };
        let Some(session_seeds) = ffi_slice(session_ticket_seeds, session_ticket_seeds_len) else {
            return DerivedKeys { aes_key: [0u8; 32], mac_key: [0u8; 32] };
        };
        let Some(packet_seeds) = ffi_slice(packet_alignment_seeds, packet_alignment_seeds_len) else {
            return DerivedKeys { aes_key: [0u8; 32], mac_key: [0u8; 32] };
        };
        let Some(config_seeds) = ffi_slice(config_cache_seeds, config_cache_seeds_len) else {
            return DerivedKeys { aes_key: [0u8; 32], mac_key: [0u8; 32] };
        };

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
        let Some(a) = ffi_slice(shard_a, shard_a_len) else {
            return BlobResult { data: std::ptr::null_mut(), len: 0, error: ffi_error_ptr("Internal error") };
        };
        let Some(b) = ffi_slice(shard_b, shard_b_len) else {
            return BlobResult { data: std::ptr::null_mut(), len: 0, error: ffi_error_ptr("Internal error") };
        };
        let Some(hash_seeds) = ffi_slice(hash_index_seeds, hash_index_seeds_len) else {
            return BlobResult { data: std::ptr::null_mut(), len: 0, error: ffi_error_ptr("Internal error") };
        };
        let Some(session_seeds) = ffi_slice(session_ticket_seeds, session_ticket_seeds_len) else {
            return BlobResult { data: std::ptr::null_mut(), len: 0, error: ffi_error_ptr("Internal error") };
        };
        let Some(packet_seeds) = ffi_slice(packet_alignment_seeds, packet_alignment_seeds_len) else {
            return BlobResult { data: std::ptr::null_mut(), len: 0, error: ffi_error_ptr("Internal error") };
        };
        let Some(config_seeds) = ffi_slice(config_cache_seeds, config_cache_seeds_len) else {
            return BlobResult { data: std::ptr::null_mut(), len: 0, error: ffi_error_ptr("Internal error") };
        };

        match decode_blob_impl(a, b, hash_seeds, session_seeds, packet_seeds, config_seeds) {
            Ok(data) => {
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
                    error: ffi_error_ptr(e),
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
        let Some(hash_seeds) = ffi_slice(hash_index_seeds, hash_index_seeds_len) else {
            return 1;
        };
        let Some(session_seeds) = ffi_slice(session_ticket_seeds, session_ticket_seeds_len) else {
            return 1;
        };
        let Some(packet_seeds) = ffi_slice(packet_alignment_seeds, packet_alignment_seeds_len) else {
            return 1;
        };
        let Some(config_seeds) = ffi_slice(config_cache_seeds, config_cache_seeds_len) else {
            return 1;
        };

        match check_window_entry_impl(fingerprint, hash_seeds, session_seeds, packet_seeds, config_seeds, route_window_primary, route_window_secondary) {
            Ok(()) => 0,
            Err(_) => 1,
        }
    }
}

pub fn table_mix_theta(
    _input_data: &[u8],
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
    let mut candidate = *seed;

    // Hostile or malformed seeds must never panic through FFI; hash-chaining keeps output deterministic.
    for _ in 0..8 {
        if let Ok(secret_key) = p256::SecretKey::from_slice(&candidate) {
            let encoded = secret_key.public_key().to_encoded_point(false);
            let bytes = encoded.as_bytes();
            let mut result = [0u8; 65];
            result[..bytes.len()].copy_from_slice(bytes);
            return result;
        }
        candidate = sha256(&candidate);
    }

    [0u8; 65]
}

pub fn hmac_sha256_finalize(secret: &[u8], data: &[u8], dest: &mut [u8; 32], unix_time: i32) {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    
    let old = u32::from_le_bytes([result[28], result[29], result[30], result[31]]);
    let masked = old ^ (unix_time as u32);
    
    dest[..28].copy_from_slice(&result[..28]);
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
    _max_padding: usize,
) -> usize {
    let mut encrypted_size = enc_size.saturating_add(data_size);
    if min_padding > 0 {
        encrypted_size = encrypted_size.saturating_add(min_padding);
    }
    let aligned = encrypted_size.saturating_add(15) & !15;
    let aligned = aligned.max(128);
    raw_size.saturating_add(aligned)
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
        let Some(slice) = ffi_slice(data, len) else {
            return std::ptr::null_mut();
        };
        let result = Box::new(sha256(slice));
        Box::into_raw(result)
    }
}

#[no_mangle]
pub extern "C" fn rust_sha256_free(hash: *mut [u8; 32]) {
    if !hash.is_null() {
        unsafe { drop(Box::from_raw(hash)) };
    }
}

#[no_mangle]
pub extern "C" fn rust_generate_x25519_public_key(seed: *const u8) -> *mut [u8; 32] {
    unsafe {
        let Some(seed_arr) = ffi_slice(seed, 32) else {
            return std::ptr::null_mut();
        };
        let mut arr = [0u8; 32];
        arr.copy_from_slice(seed_arr);
        let result = Box::new(generate_x25519_public_key(&arr));
        Box::into_raw(result)
    }
}

#[no_mangle]
pub extern "C" fn rust_generate_x25519_public_key_free(key: *mut [u8; 32]) {
    rust_sha256_free(key);
}

#[no_mangle]
pub extern "C" fn rust_generate_secp256r1_public_key(seed: *const u8) -> *mut [u8; 65] {
    unsafe {
        let Some(seed_arr) = ffi_slice(seed, 32) else {
            return std::ptr::null_mut();
        };
        let mut arr = [0u8; 32];
        arr.copy_from_slice(seed_arr);
        let result = Box::new(generate_secp256r1_public_key(&arr));
        Box::into_raw(result)
    }
}

#[no_mangle]
pub extern "C" fn rust_generate_secp256r1_public_key_free(key: *mut [u8; 65]) {
    if !key.is_null() {
        unsafe { drop(Box::from_raw(key)) };
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
        let Some(secret_slice) = ffi_slice(secret, 16) else {
            return;
        };
        let Some(data_slice) = ffi_slice(data, data_len) else {
            return;
        };
        let Some(dest_slice) = ffi_slice_mut(dest, 32) else {
            return;
        };
        let mut result = [0u8; 32];
        hmac_sha256_finalize(secret_slice, data_slice, &mut result, unix_time);
        dest_slice.copy_from_slice(&result);
    }
}

#[no_mangle]
pub extern "C" fn rust_init_grease_values(
    seed: *const u8,
    seed_len: usize,
    result_len: *mut usize,
) -> *mut u8 {
    unsafe {
        let Some(seed_slice) = ffi_slice(seed, seed_len) else {
            return std::ptr::null_mut();
        };
        if result_len.is_null() {
            return std::ptr::null_mut();
        }

        let mut result = init_grease_values(seed_slice).into_boxed_slice();
        *result_len = result.len();
        let ptr = result.as_mut_ptr();
        std::mem::forget(result);
        ptr
    }
}

#[no_mangle]
pub extern "C" fn rust_grease_values_free(data: *mut u8, len: usize) {
    if !data.is_null() && len > 0 {
        unsafe { drop(Vec::from_raw_parts(data, len, len)) };
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

#[derive(Clone, Copy)]
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
                self.rng = sha256(&self.rng).to_vec();
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
    if rng.is_empty() {
        rng.push(0);
    }
    let mut rng_pos = 0usize;
    let mut i = len;
    while i > 1 {
        if rng_pos >= rng.len() {
            let new_hash = sha256(rng);
            rng.clear();
            rng.extend_from_slice(&new_hash);
            rng_pos = 0;
        }

        let j = (rng[rng_pos] as usize) % i;
        rng_pos += 1;
        if j != i - 1 {
            items.swap(i - 1, j);
        }
        i -= 1;
    }
}

pub struct LengthCalculator {
    size: usize,
    scope_offsets: Vec<usize>,
    scope_underflow: bool,
}

impl LengthCalculator {
    pub fn new() -> Self { Self { size: 0, scope_offsets: vec![], scope_underflow: false } }
    
    pub fn append(&mut self, op: &ClientHelloOp, ctx: &ExecutionContext) {
        match op.op_type {
            ClientHelloOpType::Bytes => self.size += op.data.len(),
            ClientHelloOpType::RandomBytes | ClientHelloOpType::ZeroBytes => self.size += op.length,
            ClientHelloOpType::Domain => self.size += ctx.domain().len(),
            ClientHelloOpType::GreaseValue => self.size += 2,
            ClientHelloOpType::X25519KeyShareEntry => self.size += 36,
            ClientHelloOpType::Secp256r1KeyShareEntry => self.size += 69,
            ClientHelloOpType::X25519MlKem768KeyShareEntry => self.size += 1220,
            ClientHelloOpType::GreaseKeyShareEntry => self.size += 5,
            ClientHelloOpType::X25519PublicKey => self.size += 32,
            ClientHelloOpType::Scope16Begin => {
                self.size += 2;
                self.scope_offsets.push(self.size);
            }
            ClientHelloOpType::Scope16End => {
                if self.scope_offsets.pop().is_none() {
                    self.scope_underflow = true;
                }
            }
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
                    let target = (op.value.max(0) as usize)
                        .saturating_add(ctx.config().padding_target_entropy.max(0) as usize);
                    if self.size < target {
                        self.size = target + 4;
                    }
                }
            }
        }
    }
    
    pub fn finish(&self) -> Result<usize, &'static str> {
        if self.scope_underflow {
            return Err("Scope end without begin");
        }
        if !self.scope_offsets.is_empty() { return Err("Unbalanced scopes"); }
        Ok(self.size)
    }
}

pub struct ByteWriter {
    all: Vec<u8>,
    offset: usize,
    scope_offsets: Vec<usize>,
    rng: Vec<u8>,
    rng_pos: usize,
}

impl ByteWriter {
    pub fn new(size: usize, mut rng_seed: Vec<u8>) -> Self {
        if rng_seed.is_empty() {
            rng_seed.push(0);
        }
        Self { all: vec![0u8; size], offset: 0, scope_offsets: vec![], rng: rng_seed, rng_pos: 0 }
    }
    
    pub fn remaining(&self) -> usize { self.all.len().saturating_sub(self.offset) }
    
    fn rng_next(&mut self) -> u8 {
        if self.rng_pos >= self.rng.len() {
            self.rng = sha256(&self.rng).to_vec();
            self.rng_pos = 0;
        }
        let b = self.rng[self.rng_pos];
        self.rng_pos += 1;
        b
    }

    fn write_bytes(&mut self, data: &[u8]) {
        let end = self.offset + data.len();
        self.all[self.offset..end].copy_from_slice(data);
        self.offset = end;
    }

    fn write_zeroes(&mut self, len: usize) {
        let end = self.offset + len;
        self.all[self.offset..end].fill(0);
        self.offset = end;
    }

    fn write_random(&mut self, len: usize) {
        let start = self.offset;
        let end = start + len;
        for index in start..end {
            self.all[index] = self.rng_next();
        }
        self.offset = end;
    }
    
    pub fn append(&mut self, op: &ClientHelloOp, ctx: &ExecutionContext) {
        match op.op_type {
            ClientHelloOpType::Bytes => self.write_bytes(&op.data),
            ClientHelloOpType::RandomBytes => self.write_random(op.length),
            ClientHelloOpType::ZeroBytes => self.write_zeroes(op.length),
            ClientHelloOpType::Domain => self.write_bytes(ctx.domain()),
            ClientHelloOpType::GreaseValue => {
                let g = ctx.grease(op.value as usize);
                self.write_bytes(&[g, g]);
            }
            ClientHelloOpType::X25519KeyShareEntry => {
                self.write_bytes(&[0x00, 0x1d, 0x00, 0x20]);
                self.gen_x25519_keyshare();
            }
            ClientHelloOpType::Secp256r1KeyShareEntry => {
                self.write_bytes(&[0x00, 0x17, 0x00, 0x41]);
                self.gen_secp256r1_keyshare();
            }
            ClientHelloOpType::X25519MlKem768KeyShareEntry => {
                let pq = ctx.config().pq_group_id_override;
                self.write_bytes(&[(pq >> 8) as u8, pq as u8, 0x04, 0xc0]);
                self.gen_mlkem_keyshare();
                self.gen_x25519_keyshare();
            }
            ClientHelloOpType::GreaseKeyShareEntry => {
                let g = ctx.grease(op.value as usize);
                self.write_bytes(&[g, g, 0x00, 0x01, 0x00]);
            }
            ClientHelloOpType::X25519PublicKey => self.gen_x25519_keyshare(),
            ClientHelloOpType::Scope16Begin => {
                self.scope_offsets.push(self.offset);
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
                    self.write_bytes(&[0x00, 0x15, 0x00, override_len as u8]);
                    self.write_zeroes(override_len);
                } else if !ctx.config().has_ech {
                    let target = (op.value.max(0) as usize)
                        .saturating_add(ctx.config().padding_target_entropy.max(0) as usize);
                    let need = target.saturating_sub(self.offset);
                    if need > 0 {
                        self.write_bytes(&[0x00, 0x15, 0x00, need as u8]);
                        self.write_zeroes(need);
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
        self.write_bytes(&key);
    }
    
    fn gen_secp256r1_keyshare(&mut self) {
        let mut seed = [0u8; 32];
        for b in seed.iter_mut() { *b = self.rng_next(); }
        let key = generate_secp256r1_public_key(&seed);
        self.write_bytes(&key);
    }
    
    fn gen_mlkem_keyshare(&mut self) {
        let start = self.offset;
        for i in 0..384 {
            let a = (self.rng_next() as usize) % 3329;
            let b = (self.rng_next() as usize) % 3329;
            self.all[start + i * 3] = a as u8;
            self.all[start + i * 3 + 1] = ((a >> 8) + ((b & 15) << 4)) as u8;
            self.all[start + i * 3 + 2] = (b >> 4) as u8;
        }
        for i in 1152..1184 {
            self.all[start + i] = self.rng_next();
        }
        self.offset += 1184;
    }
    
    pub fn finalize(&mut self, secret: &[u8], unix_time: i32) {
        let mut hash_dest = [0u8; 32];
        hmac_sha256(secret, &self.all, &mut hash_dest);
        let old = u32::from_le_bytes([hash_dest[28], hash_dest[29], hash_dest[30], hash_dest[31]]);
        let masked = old ^ (unix_time as u32);
        hash_dest[28..32].copy_from_slice(&masked.to_le_bytes());
        self.all[11..43].copy_from_slice(&hash_dest);
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
    const MAX_ECH_PAYLOAD_LEN: i32 = 16 * 1024;
    const MAX_PADDING_TARGET_ENTROPY: i32 = 4 * 1024;

    if secret.len() != 16 {
        return Err("Secret must be 16 bytes");
    }
    if domain.is_empty() {
        return Err("Domain must not be empty");
    }
    if ops.is_empty() {
        return Err("ClientHello program must not be empty");
    }
    if config.padding_extension_payload_length_override > 255 {
        return Err("Padding override must fit in one byte");
    }
    if config.padding_target_entropy < 0 {
        return Err("Padding target entropy must be non-negative");
    }
    if config.padding_target_entropy > MAX_PADDING_TARGET_ENTROPY {
        return Err("Padding target entropy is too large");
    }
    if config.has_ech && config.ech_enc_key_length > 255 {
        return Err("ECH encapsulated key length must fit in one byte");
    }
    if config.has_ech && config.ech_payload_length < 0 {
        return Err("ECH payload length must be non-negative");
    }
    if config.has_ech && config.ech_payload_length > MAX_ECH_PAYLOAD_LEN {
        return Err("ECH payload length is too large");
    }
    for op in ops {
        if op.op_type == ClientHelloOpType::PaddingToTarget && op.value < 0 {
            return Err("Padding target must be non-negative");
        }
    }
    
    let ctx = ExecutionContext::new(config, domain, rng_seed);
    
    let mut calc = LengthCalculator::new();
    for op in ops {
        calc.append(op, &ctx);
    }
    let length = calc.finish()?;
    if length < 43 {
        return Err("ClientHello program is too short");
    }
    
    let mut writer = ByteWriter::new(length, ctx.rng.clone());
    for op in ops {
        writer.append(op, &ctx);
    }
    if writer.remaining() != 0 {
        return Err("ByteWriter size mismatch");
    }
    writer.finalize(secret, unix_time);
    Ok(writer.into_inner())
}

fn append_u16_be(dst: &mut Vec<u8>, value: u16) {
    dst.push((value >> 8) as u8);
    dst.push((value & 0xff) as u8);
}

fn build_default_client_hello_ops(config: ExecutorConfig) -> Vec<ClientHelloOp> {
    let mut ops = vec![
        ClientHelloOp::bytes(&[0x16, 0x03, 0x01]),
        ClientHelloOp::scope16_begin(),
        ClientHelloOp::bytes(&[0x01]),
        ClientHelloOp::scope16_begin(),
        ClientHelloOp::bytes(&[0x03, 0x03]),
        ClientHelloOp::random_bytes(32),
        ClientHelloOp::bytes(&[0x20]),
        ClientHelloOp::random_bytes(32),
        ClientHelloOp::scope16_begin(),
        ClientHelloOp::bytes(&[0x13, 0x01, 0x13, 0x02, 0x13, 0x03]),
        ClientHelloOp::scope16_end(),
        ClientHelloOp::bytes(&[0x01, 0x00]),
        ClientHelloOp::scope16_begin(),
    ];

    // SNI extension with runtime domain bytes.
    ops.extend_from_slice(&[
        ClientHelloOp::bytes(&[0x00, 0x00]),
        ClientHelloOp::scope16_begin(),
        ClientHelloOp::scope16_begin(),
        ClientHelloOp::bytes(&[0x00]),
        ClientHelloOp::scope16_begin(),
        ClientHelloOp::domain(),
        ClientHelloOp::scope16_end(),
        ClientHelloOp::scope16_end(),
        ClientHelloOp::scope16_end(),
    ]);

    // supported_groups extension.
    let mut groups = vec![0x00, 0x1d, 0x00, 0x17];
    if config.pq_group_id_override != 0 {
        append_u16_be(&mut groups, config.pq_group_id_override);
    }
    ops.extend_from_slice(&[
        ClientHelloOp::bytes(&[0x00, 0x0a]),
        ClientHelloOp::scope16_begin(),
        ClientHelloOp::scope16_begin(),
        ClientHelloOp::bytes(&groups),
        ClientHelloOp::scope16_end(),
        ClientHelloOp::scope16_end(),
    ]);

    // signature_algorithms extension.
    ops.extend_from_slice(&[
        ClientHelloOp::bytes(&[0x00, 0x0d]),
        ClientHelloOp::scope16_begin(),
        ClientHelloOp::scope16_begin(),
        ClientHelloOp::bytes(&[0x04, 0x03, 0x08, 0x04, 0x08, 0x05]),
        ClientHelloOp::scope16_end(),
        ClientHelloOp::scope16_end(),
    ]);

    // key_share extension.
    ops.extend_from_slice(&[
        ClientHelloOp::bytes(&[0x00, 0x33]),
        ClientHelloOp::scope16_begin(),
        ClientHelloOp::scope16_begin(),
        ClientHelloOp::x25519_key_share_entry(),
    ]);
    if config.pq_group_id_override != 0 {
        ops.push(ClientHelloOp::x25519_ml_kem_768_key_share_entry());
    }
    ops.extend_from_slice(&[
        ClientHelloOp::scope16_end(),
        ClientHelloOp::scope16_end(),
    ]);

    // ALPN extension.
    ops.extend_from_slice(&[
        ClientHelloOp::bytes(&[0x00, 0x10]),
        ClientHelloOp::scope16_begin(),
        ClientHelloOp::scope16_begin(),
    ]);
    if config.force_http11_only_alpn {
        ops.push(ClientHelloOp::bytes(&[0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']));
    } else {
        ops.push(ClientHelloOp::bytes(&[0x02, b'h', b'2']));
        ops.push(ClientHelloOp::bytes(&[0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']));
    }
    ops.extend_from_slice(&[ClientHelloOp::scope16_end(), ClientHelloOp::scope16_end()]);

    if config.alps_type != 0 {
        let mut alps = Vec::new();
        append_u16_be(&mut alps, config.alps_type);
        ops.push(ClientHelloOp::bytes(&alps));
        ops.push(ClientHelloOp::scope16_begin());
        ops.push(ClientHelloOp::zero_bytes(2));
        ops.push(ClientHelloOp::scope16_end());
    }

    if config.has_ech {
        ops.push(ClientHelloOp::bytes(&[0xfe, 0x0d]));
        ops.push(ClientHelloOp::scope16_begin());
        let mut ech_header = Vec::new();
        ech_header.push(config.ech_outer_type);
        append_u16_be(&mut ech_header, config.ech_kdf_id);
        append_u16_be(&mut ech_header, config.ech_aead_id);
        let enc_key_len = config.ech_enc_key_length.max(0) as usize;
        ech_header.push(enc_key_len.min(255) as u8);
        ops.push(ClientHelloOp::bytes(&ech_header));
        if enc_key_len > 0 {
            ops.push(ClientHelloOp::random_bytes(enc_key_len));
        }
        let payload_len = config.ech_payload_length.max(0) as usize;
        if payload_len > 0 {
            ops.push(ClientHelloOp::random_bytes(payload_len));
        }
        ops.push(ClientHelloOp::scope16_end());
    }

    let padding_target = 512i32;
    ops.push(ClientHelloOp::padding_to_target(padding_target));
    ops.push(ClientHelloOp::scope16_end());
    ops.push(ClientHelloOp::scope16_end());
    ops.push(ClientHelloOp::scope16_end());
    ops
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
        if !result_len.is_null() {
            *result_len = 0;
        }

        let Some(domain_slice) = ffi_slice(domain, domain_len) else {
            return std::ptr::null_mut();
        };
        let Some(secret_slice) = ffi_slice(secret, 16) else {
            return std::ptr::null_mut();
        };
        let Some(rng_slice) = ffi_slice(rng_seed, rng_seed_len) else {
            return std::ptr::null_mut();
        };
        if result_len.is_null() {
            return std::ptr::null_mut();
        }

        let rng_vec = rng_slice.to_vec();
        let ops = build_default_client_hello_ops(config);
        
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

