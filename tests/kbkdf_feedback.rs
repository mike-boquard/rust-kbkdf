mod aes_cmac_prf;

use aes_cmac_prf::*;

use rust_kbkdf::{kbkdf, CounterLocation, FeedbackMode, FixedInput, InputType, KDFMode};

#[test]
fn cmac_aes_128_no_counter_512_bit_output_with_iv() {
    let key = hex::decode("5c996c922f65de97d4408373229814c6").expect("Failed to decode key");
    let iv = hex::decode("28dc945cb8337ab5336c3e9b5bad21c7").expect("Failed to decode iv");
    let fixed_input = hex::decode("62afe5fed91e797221a854336b0aadd8a05ad0e3c8345729897b2efcec5a1178a2fa4c063007b67a7015e0d6b7271ea8d86b44").expect("Failed to decode fixed input");

    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new();

    let mode = KDFMode::FeedbackMode(FeedbackMode {
        iv: Some(iv.as_slice()),
        counter_length: None,
    });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::NoCounter,
    });

    let mut output = vec![0; 512 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("88a9aae193abdd3fe8143bab66014ae41dc2d12ea9d08f5871588fc5d827924eb9942989d7a36d4b3b107997566472cad5942bd13cb5cff32b9dae30f1bb6300").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_no_counter_512_bit_output_no_iv() {
    let key = hex::decode("3a139e1aa922d3373b2674e303a6cc59").expect("Failed to decode key");
    let fixed_input = hex::decode("4d91720a2cff429fc1c0b79e845c5029b3c9535935cbeee5808dea82b8453ffcbed8f54e44500fd82ded679f843c569297ed82").expect("Failed to decode fixed input");

    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new();

    let mode = KDFMode::FeedbackMode(FeedbackMode {
        iv: None,
        counter_length: None,
    });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::NoCounter,
    });

    let mut output = vec![0; 512 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("2c9b849dc36efc1aff45030cf2288eba71faf176172a2688576605bc5f4f66a95850b096c2f9a4416eb743f8d14f8ba4cffbdc3174f63ca861765dc8f5dab59a").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_32_bit_counter_before_iter_512_bit_output_iv() {
    let key = hex::decode("fc126023dfc9fb6cd56fc5602c05657c").expect("Failed to decode key");
    let iv = hex::decode("a736f838049448e04845b6b0ec2d6f63").expect("Failed to decode iv");
    let fixed_input = hex::decode("8068d7b98b8c4528ae8555ab5ae67c71a92b664245ec7d333b22479c5072421e7239761494e45eff09297737a1bb2c39fe9f1f").expect("Failed to decode fixed input");

    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new();

    let mode = KDFMode::FeedbackMode(FeedbackMode {
        iv: Some(iv.as_slice()),
        counter_length: Some(32),
    });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeIter,
    });

    let mut output = vec![0; 512 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("b9824ad55e6913151a3f736f5fd6bf0807e1acb8c7ed0082df138ba1cc0e6db3c667c8abae707cdf920f48bf77765437407b564333796c037b0378f8f431114c").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_32_bit_counter_after_iter_512_bit_output_iv() {
    let key = hex::decode("607a069650470c92021850add7506fed").expect("Failed to decode key");
    let iv = hex::decode("bcc557c72df7ed5163e39bf201d2354f").expect("Failed to decode iv");
    let fixed_input = hex::decode("d465d19beb40b57d51eb30f9b8170f33a07ffbf03e41b6ade6338cb85d75b910bc0af62e3a228bacaf68eb099d1d315ce09395").expect("Failed to decode fixed input");

    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new();

    let mode = KDFMode::FeedbackMode(FeedbackMode {
        iv: Some(iv.as_slice()),
        counter_length: Some(32),
    });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterIter,
    });

    let mut output = vec![0; 512 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("d5741964649e1a4f825493f933cdc02a8edb6001a3986050cf7511184e4794cdec967e631d5b323f39315bf4bd2c45b692d632dfb6bdb86d509845fe63df550d").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_32_bit_counter_after_fixed_512_bit_output_iv() {
    let key = hex::decode("1edbd1bb1ff8abda4cb51d656ac83405").expect("Failed to decode key");
    let iv = hex::decode("0b847773cd50a9984653a8d7bffe41e1").expect("Failed to decode iv");
    let fixed_input = hex::decode("a74a8c3b5b6c504f1b72b0f22ed380de8eff38f541d0991dd2f54c2259a2ea9e6907a3528e6fd5591aff710685308adc97d423").expect("Failed to decode fixed input");

    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new();

    let mode = KDFMode::FeedbackMode(FeedbackMode {
        iv: Some(iv.as_slice()),
        counter_length: Some(32),
    });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 512 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("f6f3c5a17ef294e1818e5a4a7b3194f728fb65befba2083ca8ba0a2585db4c08f8f5a5e0b4f94fb3cf640255277cddf628542693debf34ec1f7d2d1612c233be").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}
