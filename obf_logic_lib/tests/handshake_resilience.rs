use obf_logic_lib::{client_hello_execute, ClientHelloOp, ExecutorConfig};

fn make_permutation_part(byte: u8, repeats: usize) -> Vec<ClientHelloOp> {
    vec![ClientHelloOp::bytes(&vec![byte; repeats])]
}

#[test]
fn wide_permutation_matrix_does_not_panic_or_oob() {
    let mut parts = Vec::new();
    for i in 0..96u8 {
        parts.push(make_permutation_part(i, (i as usize % 5) + 1));
    }
    let ops = vec![
        ClientHelloOp::bytes(&[0x16, 0x03, 0x01]),
        ClientHelloOp::permutation(parts),
        ClientHelloOp::bytes(&[0u8; 48]),
    ];

    let result = std::panic::catch_unwind(|| {
        client_hello_execute(
            &ops,
            b"example.com",
            &[0xAB; 16],
            123,
            ExecutorConfig::default(),
            vec![0x55],
        )
    });

    assert!(result.is_ok(), "wide permutation must never panic");
    assert!(result.unwrap().is_ok(), "wide permutation should execute");
}

#[test]
fn negative_padding_entropy_is_rejected_fail_closed() {
    let mut cfg = ExecutorConfig::default();
    cfg.padding_target_entropy = -1;

    let ops = vec![
        ClientHelloOp::bytes(&[0u8; 64]),
        ClientHelloOp::padding_to_target(128),
    ];

    let result = std::panic::catch_unwind(|| {
        client_hello_execute(&ops, b"example.com", &[0x11; 16], 1, cfg, vec![1, 2, 3, 4])
    });

    assert!(result.is_ok(), "negative entropy must not panic");
    assert!(result.unwrap().is_err(), "negative entropy must be rejected");
}

#[test]
fn negative_padding_target_is_rejected_fail_closed() {
    let ops = vec![
        ClientHelloOp::bytes(&[0u8; 64]),
        ClientHelloOp::padding_to_target(-1),
    ];

    let result = std::panic::catch_unwind(|| {
        client_hello_execute(
            &ops,
            b"example.com",
            &[0x22; 16],
            2,
            ExecutorConfig::default(),
            vec![5, 6, 7, 8],
        )
    });

    assert!(result.is_ok(), "negative target must not panic");
    assert!(result.unwrap().is_err(), "negative target must be rejected");
}

#[test]
fn oversized_ech_payload_is_rejected_fail_closed() {
    let mut cfg = ExecutorConfig::default();
    cfg.has_ech = true;
    cfg.ech_payload_length = 1_000_000;

    let ops = vec![ClientHelloOp::bytes(&[0u8; 64])];

    let result = std::panic::catch_unwind(|| {
        client_hello_execute(&ops, b"example.com", &[0x33; 16], 3, cfg, vec![9, 10, 11, 12])
    });

    assert!(result.is_ok(), "oversized ECH payload must not panic");
    assert!(result.unwrap().is_err(), "oversized ECH payload must be rejected");
}
