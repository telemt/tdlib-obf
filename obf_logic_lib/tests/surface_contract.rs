use std::ffi::CStr;
use std::os::raw::c_char;

use obf_logic_lib::{
    init_grease_values, rust_check_window_entry, rust_decode_blob, rust_free_blob,
    rust_generate_secp256r1_public_key, rust_init_grease_values, rust_grease_values_free, rust_sha256, BlobResult,
    ExecutorConfig, rust_client_hello_execute, rust_client_hello_free,
};

fn assert_error_message(result: BlobResult, expected: &str) {
    assert!(result.data.is_null());
    assert!(!result.error.is_null());

    let error = unsafe { CStr::from_ptr(result.error as *const c_char) };
    assert_eq!(error.to_str().unwrap(), expected);
}

#[test]
fn decode_blob_exposes_nul_terminated_error_message() {
    let result = rust_decode_blob(
        [1u8].as_ptr(),
        1,
        [2u8].as_ptr(),
        1,
        [].as_ptr(),
        0,
        [].as_ptr(),
        0,
        [].as_ptr(),
        0,
        [].as_ptr(),
        0,
    );

    assert_error_message(result, "Invalid blob size");
}

#[test]
fn grease_values_ffi_returns_flat_owned_buffer() {
    let seed = [0x01u8, 0x1a, 0x2a, 0x3a, 0x4b, 0x5a, 0x6a, 0x7a];
    let expected = init_grease_values(&seed);
    let mut len = 0usize;

    let ptr = rust_init_grease_values(seed.as_ptr(), seed.len(), &mut len);
    assert_eq!(len, expected.len());
    let actual = unsafe { std::slice::from_raw_parts(ptr, len) };
    assert_eq!(actual, expected.as_slice());

    rust_grease_values_free(ptr, len);
}

#[test]
fn zero_length_blob_free_is_a_noop() {
    rust_free_blob(std::ptr::null_mut(), 0);
}

#[test]
fn hash_export_rejects_null_input_with_nonzero_length() {
    let ptr = rust_sha256(std::ptr::null(), 1);
    assert!(ptr.is_null());
}

#[test]
fn grease_values_export_rejects_null_seed_pointer() {
    let mut len = 123usize;
    let ptr = rust_init_grease_values(std::ptr::null(), 4, &mut len);
    assert!(ptr.is_null());
    assert_eq!(len, 123);
}

#[test]
fn window_entry_export_fails_closed_on_invalid_seed_pointer() {
    let status = rust_check_window_entry(
        0,
        std::ptr::null(),
        4,
        [].as_ptr(),
        0,
        [].as_ptr(),
        0,
        [].as_ptr(),
        0,
        0,
        0,
    );
    assert_eq!(status, 1);
}

#[test]
fn public_key_export_rejects_null_seed_pointer() {
    let ptr = rust_generate_secp256r1_public_key(std::ptr::null());
    assert!(ptr.is_null());
}

#[test]
fn client_hello_export_requires_result_length_pointer() {
    let ptr = rust_client_hello_execute(
        b"example.com".as_ptr(),
        b"example.com".len(),
        [0x11u8; 16].as_ptr(),
        0,
        ExecutorConfig::default(),
        [0x22u8; 8].as_ptr(),
        8,
        std::ptr::null_mut(),
    );
    assert!(ptr.is_null());
}

#[test]
fn client_hello_export_clears_result_len_on_failure() {
    let mut len = 777usize;
    let ptr = rust_client_hello_execute(
        std::ptr::null(),
        4,
        [0x11u8; 16].as_ptr(),
        0,
        ExecutorConfig::default(),
        [0x22u8; 8].as_ptr(),
        8,
        &mut len,
    );

    assert!(ptr.is_null());
    assert_eq!(len, 0, "result length must be cleared on failure");
}

#[test]
fn client_hello_export_returns_deterministic_nonempty_buffer() {
    let domain = b"example.com";
    let secret = [0x11u8; 16];
    let rng_seed = [0x22u8; 32];
    let mut len_a = 0usize;
    let mut len_b = 0usize;

    let ptr_a = rust_client_hello_execute(
        domain.as_ptr(),
        domain.len(),
        secret.as_ptr(),
        1234,
        ExecutorConfig::default(),
        rng_seed.as_ptr(),
        rng_seed.len(),
        &mut len_a,
    );
    let ptr_b = rust_client_hello_execute(
        domain.as_ptr(),
        domain.len(),
        secret.as_ptr(),
        1234,
        ExecutorConfig::default(),
        rng_seed.as_ptr(),
        rng_seed.len(),
        &mut len_b,
    );

    assert!(!ptr_a.is_null());
    assert!(!ptr_b.is_null());
    assert!(len_a > 43);
    assert_eq!(len_a, len_b);

    let out_a = unsafe { std::slice::from_raw_parts(ptr_a, len_a) };
    let out_b = unsafe { std::slice::from_raw_parts(ptr_b, len_b) };

    assert_eq!(&out_a[0..3], &[0x16, 0x03, 0x01]);
    assert_eq!(out_a, out_b);
    assert!(out_a.windows(domain.len()).any(|w| w == domain));

    rust_client_hello_free(ptr_a, len_a);
    rust_client_hello_free(ptr_b, len_b);
}

#[test]
fn client_hello_export_changes_with_rng_seed() {
    let domain = b"example.com";
    let secret = [0x11u8; 16];
    let mut len_a = 0usize;
    let mut len_b = 0usize;
    let seed_a = [0x01u8; 32];
    let seed_b = [0x02u8; 32];

    let ptr_a = rust_client_hello_execute(
        domain.as_ptr(),
        domain.len(),
        secret.as_ptr(),
        1234,
        ExecutorConfig::default(),
        seed_a.as_ptr(),
        seed_a.len(),
        &mut len_a,
    );
    let ptr_b = rust_client_hello_execute(
        domain.as_ptr(),
        domain.len(),
        secret.as_ptr(),
        1234,
        ExecutorConfig::default(),
        seed_b.as_ptr(),
        seed_b.len(),
        &mut len_b,
    );

    assert!(!ptr_a.is_null());
    assert!(!ptr_b.is_null());

    let out_a = unsafe { std::slice::from_raw_parts(ptr_a, len_a) };
    let out_b = unsafe { std::slice::from_raw_parts(ptr_b, len_b) };

    assert_ne!(out_a, out_b);

    rust_client_hello_free(ptr_a, len_a);
    rust_client_hello_free(ptr_b, len_b);
}