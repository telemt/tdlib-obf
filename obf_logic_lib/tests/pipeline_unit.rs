use obf_logic_lib::{calc_stealth_padding, derive_keys, reassemble_blob, ClientHelloOp, ClientHelloOpType};

#[test]
fn derive_keys_splits_aes_and_mac_material() {
    let key_material = b"test_key_material";
    let keys = derive_keys(key_material);
    assert_ne!(keys.aes_key, keys.mac_key);
}

#[test]
fn reassemble_blob_xors_matching_shards() {
    let left = vec![0x01, 0x02, 0x03, 0x04];
    let right = vec![0xff, 0xfe, 0xfd, 0xfc];
    let result = reassemble_blob(&left, &right).unwrap();
    assert_eq!(result, vec![0xfe, 0xfc, 0xfe, 0xf8]);
}

#[test]
fn stealth_padding_enforces_minimum_encrypted_size() {
    let size = calc_stealth_padding(100, 4, 12, 0, 0);
    assert!(size >= 128 + 12);
}

#[test]
fn client_hello_bytes_op_reports_its_variant() {
    let op = ClientHelloOp::bytes(b"\x16\x03\x01");
    assert_eq!(op.op_type, ClientHelloOpType::Bytes);
}