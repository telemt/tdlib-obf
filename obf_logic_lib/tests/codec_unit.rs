use obf_logic_lib::generate_secp256r1_public_key;
use p256::elliptic_curve::sec1::ToEncodedPoint;

#[test]
fn secp256r1_public_key_matches_p256_reference() {
    let seed = [7u8; 32];
    let secret = p256::SecretKey::from_slice(&seed).expect("seed must map to a valid P-256 scalar");
    let expected = secret.public_key().to_encoded_point(false);
    let actual = generate_secp256r1_public_key(&seed);

    assert_eq!(actual.as_slice(), expected.as_bytes());
}

#[test]
fn secp256r1_public_key_handles_zero_seed_without_panic() {
    let result = std::panic::catch_unwind(|| generate_secp256r1_public_key(&[0u8; 32]));
    assert!(result.is_ok(), "invalid scalar input must not panic");

    let key = result.unwrap();
    assert_eq!(key.len(), 65);
    assert_eq!(key[0], 0x04, "output must be an uncompressed SEC1 point");
}