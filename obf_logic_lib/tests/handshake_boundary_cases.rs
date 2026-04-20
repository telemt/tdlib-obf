use obf_logic_lib::{client_hello_execute, ClientHelloOp, ExecutorConfig};

#[test]
fn short_rng_seed_with_random_bytes_does_not_panic() {
    let ops = vec![ClientHelloOp::random_bytes(64)];

    let result = std::panic::catch_unwind(|| {
        client_hello_execute(
            &ops,
            b"example.com",
            &[0x11; 16],
            123,
            ExecutorConfig::default(),
            vec![1, 2, 3],
        )
    });

    assert!(result.is_ok(), "execution must not panic on short RNG seed");
    assert!(
        result.unwrap().is_ok(),
        "execution should complete for valid program"
    );
}

#[test]
fn short_rng_seed_with_permutation_does_not_panic() {
    let prefix = vec![0xAA; 50];
    let ops = vec![
        ClientHelloOp::bytes(&prefix),
        ClientHelloOp::permutation(vec![
            vec![ClientHelloOp::bytes(&[0x01, 0x02])],
            vec![ClientHelloOp::bytes(&[0x03, 0x04])],
        ]),
    ];

    let result = std::panic::catch_unwind(|| {
        client_hello_execute(
            &ops,
            b"example.com",
            &[0x22; 16],
            77,
            ExecutorConfig::default(),
            vec![9],
        )
    });

    assert!(result.is_ok(), "permutation path must not panic");
    assert!(result.unwrap().is_ok(), "permutation path should succeed");
}

#[test]
fn oversized_padding_override_is_rejected_without_panic() {
    let mut cfg = ExecutorConfig::default();
    cfg.padding_extension_payload_length_override = 300;

    let ops = vec![ClientHelloOp::bytes(&[0u8; 64]), ClientHelloOp::padding_to_target(128)];

    let result = std::panic::catch_unwind(|| {
        client_hello_execute(&ops, b"example.com", &[0x44; 16], 9, cfg, vec![1, 2, 3, 4])
    });

    assert!(result.is_ok(), "oversized padding override must not panic");
    assert!(result.unwrap().is_err(), "invalid override must be rejected");
}

#[test]
fn oversized_ech_enc_key_length_is_rejected_without_panic() {
    let mut cfg = ExecutorConfig::default();
    cfg.has_ech = true;
    cfg.ech_enc_key_length = 512;

    let ops = vec![ClientHelloOp::bytes(&[0u8; 64])];

    let result = std::panic::catch_unwind(|| {
        client_hello_execute(&ops, b"example.com", &[0x55; 16], 9, cfg, vec![5, 6, 7, 8])
    });

    assert!(result.is_ok(), "oversized ECH key length must not panic");
    assert!(result.unwrap().is_err(), "oversized ECH key length must be rejected");
}

#[test]
fn scope_end_without_scope_begin_is_rejected_without_panic() {
    let ops = vec![ClientHelloOp::scope16_end()];

    let result = std::panic::catch_unwind(|| {
        client_hello_execute(
            &ops,
            b"example.com",
            &[0x66; 16],
            101,
            ExecutorConfig::default(),
            vec![1, 2, 3, 4],
        )
    });

    assert!(result.is_ok(), "unbalanced scope must not panic");
    assert!(result.unwrap().is_err(), "unbalanced scope must be rejected");
}

#[test]
fn short_rng_seed_stress_matrix_does_not_panic() {
    for seed_len in 0usize..64 {
        let rng_seed = vec![0xA5; seed_len];
        let ops = vec![
            ClientHelloOp::bytes(&[0x16, 0x03, 0x01]),
            ClientHelloOp::random_bytes(96),
            ClientHelloOp::permutation(vec![
                vec![ClientHelloOp::bytes(&[0x10, 0x11, 0x12])],
                vec![ClientHelloOp::bytes(&[0x20, 0x21, 0x22])],
                vec![ClientHelloOp::bytes(&[0x30, 0x31, 0x32])],
            ]),
        ];

        let result = std::panic::catch_unwind(|| {
            client_hello_execute(
                &ops,
                b"example.com",
                &[0x77; 16],
                202,
                ExecutorConfig::default(),
                rng_seed,
            )
        });

        assert!(
            result.is_ok(),
            "seed_len={seed_len}: execution must not panic under stress"
        );
        assert!(
            result.unwrap().is_ok(),
            "seed_len={seed_len}: valid stress program should execute"
        );
    }
}