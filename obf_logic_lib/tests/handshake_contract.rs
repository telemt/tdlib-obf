use obf_logic_lib::{client_hello_execute, ClientHelloOp, ExecutorConfig};

#[test]
fn empty_client_hello_program_returns_error_instead_of_panicking() {
    let result = std::panic::catch_unwind(|| {
        client_hello_execute(
            &[],
            b"example.com",
            &[0x11; 16],
            123,
            ExecutorConfig::default(),
            vec![1, 2, 3, 4],
        )
    });

    assert!(result.is_ok(), "empty program must not panic");
    assert!(result.unwrap().is_err(), "empty program must be rejected");
}

#[test]
fn byte_program_preserves_non_mac_regions() {
    let input: Vec<u8> = (0..64).collect();
    let ops = vec![ClientHelloOp::bytes(&input)];

    let output = client_hello_execute(
        &ops,
        b"example.com",
        &[0x22; 16],
        7,
        ExecutorConfig::default(),
        vec![9, 8, 7, 6],
    )
    .expect("byte-only program should succeed");

    assert_eq!(&output[..11], &input[..11]);
    assert_eq!(&output[43..], &input[43..]);
}