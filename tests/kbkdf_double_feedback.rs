mod aes_cmac_prf;

use aes_cmac_prf::*;

use rust_kbkdf::{kbkdf, CounterLocation, DoublePipelineIterationMode, FixedInput, InputType, KDFMode};

#[test]
fn cmac_aes_128_no_counter_512_bit_output() {
    let key = hex::decode("ada2452f1f141a82c7a1b7d3e09ffed1").expect("Failed to decode key");
    let fixed_input = hex::decode("335660eb265d2044efa06eacd848d3f9f57d219011343318f3a964df4a6fb1bf6cbdee711c7fcbe73b8f257f992e47e8b065af").expect("Failed to decode fixed input");

    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new();

    let mode = KDFMode::DoublePipelineIterationMode(DoublePipelineIterationMode {
        counter_length: None,
    });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::NoCounter,
    });

    let mut output = vec![0; 512 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("a73bd29176e38e761222ae07d639181f4b2c555a3b261815cde5d88a67c8b95c58b6b66ea4f10608c6d799b051519fc8e89de00cdc556350a7d966475086f9af").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_32_bit_counter_before_iter_512_bit() {
    let key = hex::decode("f862c0f1fbec48df982d9c4013807912").expect("Failed to decode key");
    let fixed_input = hex::decode("7d2bba9a4b121a33bc54b5515df6014407710d698d9d768a9a096a0faeb3ad2cb15ed63d9b6490e7647c814b8bac2a842662e7").expect("Failed to decode fixed input");

    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new();

    let mode = KDFMode::DoublePipelineIterationMode(DoublePipelineIterationMode {
        counter_length: Some(32),
    });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeIter,
    });

    let mut output = vec![0; 512 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("19f69a9024217d0beba61f4b8aba60267e9e850a96e7ce5dafebfa6add0df2691f53043223d6300f295d44cb31ea57b0869f5c3840ae003c293a5cdd44af46be").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_32_bit_counter_after_iter_512_bit() {
    let key = hex::decode("34f0c2542bfe13c7149b68c8a1ef636b").expect("Failed to decode key");
    let fixed_input = hex::decode("daefcc52d6e32e1614109268933087fce3d64a5a6f111ba1a8d343a1e388a1752aaea93853be52864997a81c84b04c4f3ff3bd").expect("Failed to decode fixed input");

    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new();

    let mode = KDFMode::DoublePipelineIterationMode(DoublePipelineIterationMode {
        counter_length: Some(32),
    });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterIter,
    });

    let mut output = vec![0; 512 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("fc0eae673e7db3c4660668e187bcd81d5ca9b89213d8d741e71c9bab89bb4fb3c4df541d89a8117f0f56b0f15111ae28abf81fb7d7349fbbcaf01137e4d73527").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_32_bit_counter_after_fixed_512_bit() {
    let key = hex::decode("b65ea7c14d21cbad94575d668929b8ed").expect("Failed to decode key");
    let fixed_input = hex::decode("13d47f74b114e79a80a04d281389731d7dfca2b5753036782b8790a97003fa50a5653dda69fc4cc7a79ba59497c17025dbc3fb").expect("Failed to decode fixed input");

    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new();

    let mode = KDFMode::DoublePipelineIterationMode(DoublePipelineIterationMode {
        counter_length: Some(32),
    });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 512 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("32de17b47de8fc08f756734a2e51488b41105e20f0f811f9b05e583e476691f1d77e6685abdc9f919a38e2cfe3ca5c91c3c7d4a52f229b5f25eb9b70750ebc10").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}
