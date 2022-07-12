// Author's note:
// I kind of went to town on the AES-192 PRF and did all the combos (different counter length,
// output length, counter position, etc.) and then I realized that was a lot of work to repeat the
// same thing over and over again, so after AES-128, I'm just going to do the largest output, with
// the largest counter length, for each position

mod aes_cmac_prf;

use aes_cmac_prf::*;

use rust_kbkdf::{kbkdf, CounterLocation, CounterMode, FixedInput, InputType, KDFMode};
use openssl::symm::Cipher;

#[test]
fn cmac_aes_128_before_fixed_eight_bits_128_bit_output() {
    let key = hex::decode("dff1e50ac0b69dc40f1051d46c2b069c").expect("Failed to decode key");
    let fixed_input = hex::decode("c16e6e02c5a3dcc8d78b9ac1306877761310455b4e41469951d9e6c2245a064b33fd8c3b01203a7824485bf0a64060c4648b707d2607935699316ea5").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 8 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 128 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("8be8f0869b3c0ba97b71863d1b9f7813").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_before_fixed_eight_bits_256_bit_output() {
    let key = hex::decode("682e814d872397eba71170a693514904").expect("Failed to decode key");
    let fixed_input = hex::decode("e323cdfa7873a0d72cd86ffb4468744f097db60498f7d0e3a43bafd2d1af675e4a88338723b1236199705357c47bf1d89b2f4617a340980e6331625c").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 8 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 256 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("dac9b6ca405749cfb065a0f1e42c7c4224d3d5db32fdafe9dee6ca193316f2c7")
            .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_before_fixed_eight_bits_160_bit_output() {
    let key = hex::decode("58618d4c998ed1d2efc2fcfe9bd2b78b").expect("Failed to decode key");
    let fixed_input = hex::decode("d02fd07ba3ce8d82b0b561dfed84211e71eef1ae51c1125490595cc11b8b5ab01de0d279c36b632ca1f131621883672cfebedc821b26093d53adafc7").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 8 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 160 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode("6141172f887da52aaa26d844af28f56c82689a99")
        .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_before_fixed_eight_bits_320_bit_output() {
    let key = hex::decode("bb31eef5a2ca3bfb342c5800fee67313").expect("Failed to decode key");
    let fixed_input = hex::decode("f85ae18f15ce1a5e036d6e3fd227243a9863f88ef532ce1da810b6639c0928f9b99fe909487d3748cff857cdb790f89e09d8c634dccb616cf7a2663a").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 8 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "8923d38effde99e24f67dec9330c4f1b874fc382ad644140e73a8e406f405d3fe4b4730b7291275a",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_before_fixed_16_bits_128_bit_output() {
    let key = hex::decode("30ec5f6fa1def33cff008178c4454211").expect("Failed to decode key");
    let fixed_input = hex::decode("c95e7b1d4f2570259abfc05bb00730f0284c3bb9a61d07259848a1cb57c81d8a6c3382c500bf801dfc8f70726b082cf4c3fa34386c1e7bf0e5471438").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 16 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 128 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("00018fff9574994f5c4457f461c7a67e").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_before_fixed_16_bits_256_bit_output() {
    let key = hex::decode("145c9e9365041f075ebde8ce26aa2149").expect("Failed to decode key");
    let fixed_input = hex::decode("0d39b1c9c34d95b5b521971828c81d9f2dbdbc4af2ddd14f628721117e5c39faa030522b93cc07beb8f142fe36f674942453ec5518ca46c3e6842a73").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 16 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 256 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("8a204ce7eab882fae3e2b8317fe431dba16dabb8fe5235525e7b61135e1b3c16")
            .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_before_fixed_16_bits_160_bit_output() {
    let key = hex::decode("2ed9d08c5585c1b5a49d782486c8454d").expect("Failed to decode key");
    let fixed_input = hex::decode("69a3ca2b877300dbf4135782a80000e0ec91a4e14312e7bf1d90cb4082f5c59448fc9cc677693fc46395ffd71b10348d2ba4e016aaa18a08300236d1").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 16 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 160 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode("364385337a9a6c0b89b57f624ed7e2bece41bee9")
        .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_before_fixed_16_bits_320_bit_output() {
    let key = hex::decode("e688c545e5ea41547f7817e484434980").expect("Failed to decode key");
    let fixed_input = hex::decode("321fbaf2f7f56e43b289e9f57c7d80c14335e612041d84cce9eb4f35ec7aaf9204b5b985709c079f8193124f6bb70f9f2d3d6957b3d2f5a280db6125").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 16 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "f92d496653c757d046ada7535baee4b8b3054cc40fbef4f98776a40c37dc86bafe62d5c74ad33a35",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_before_fixed_24_bits_128_bit_output() {
    let key = hex::decode("ca1cf43e5ccd512cc719a2f9de41734c").expect("Failed to decode key");
    let fixed_input = hex::decode("e3884ac963196f02ddd09fc04c20c88b60faa775b5ef6feb1faf8c5e098b5210e2b4e45d62cc0bf907fd68022ee7b15631b5c8daf903d99642c5b831").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 24 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 128 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("1cb2b12326cc5ec1eba248167f0efd58").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_before_fixed_24_bits_256_bit_output() {
    let key = hex::decode("3d045a1b7d8f7dac45d7d16223853520").expect("Failed to decode key");
    let fixed_input = hex::decode("3e482607c7ffba6374b7dab6f2134e8f46eb475cfbf67ab94bdf400e35ce70e7eb51b706af22b7532345a3cc5fd57f6ee7ef68630fd87a5594c72f15").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 24 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 256 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("94c01dbded425d1c15fbef0c2f19ee1629b658c6a3de6953df1b8ca92dc01477")
            .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_before_fixed_24_bits_160_bit_output() {
    let key = hex::decode("e54b57ec5777a9892837b15344e365d0").expect("Failed to decode key");
    let fixed_input = hex::decode("38e92f1241af9231e46499a330e3ae0eeb50caa171f0ad11d9ccc946f41314a1ec4706b42e8345a49403aba78626de27f2bda22e84820d005b306ad8").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 24 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 160 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode("6acb93d928755d54f1c5204c514c4ee3f4cb40ac")
        .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_before_fixed_24_bits_320_bit_output() {
    let key = hex::decode("ca411d3be6adefd3a3e540b3c58fcb00").expect("Failed to decode key");
    let fixed_input = hex::decode("493569d3311a0e8e3de2ab3737247dce0e339097b973c254090845c1148c16af827bd90d8a775dc9b0fe3b18c3fbe8f110a52db7b3f89ac72abfeb5b").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 24 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "1c4c704da046b84cce08a95241d47297375ce2dc735f0774909fa8527aab317b676bc28ad315c15c",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_before_fixed_32_bits_128_bit_output() {
    let key = hex::decode("c10b152e8c97b77e18704e0f0bd38305").expect("Failed to decode key");
    let fixed_input = hex::decode("98cd4cbbbebe15d17dc86e6dbad800a2dcbd64f7c7ad0e78e9cf94ffdba89d03e97eadf6c4f7b806caf52aa38f09d0eb71d71f497bcc6906b48d36c4").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 128 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("26faf61908ad9ee881b8305c221db53f").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_before_fixed_32_bits_256_bit_output() {
    let key = hex::decode("009300d265d1f1b28b505dccc162f4f8").expect("Failed to decode key");
    let fixed_input = hex::decode("5ac373d42ed92427d8ff6cfff7eae13d66d3c7e536cc749859e2a49e3eea2ad846c9fbb7ddd99a1e6a54a89a87db98db6b8229f577b552e09aeed5e6").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 256 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("c666d91f931606882bf214ebe79cd25a02810c7ab6ced75cd3fabd027f0de54e")
            .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_before_fixed_32_bits_160_bit_output() {
    let key = hex::decode("93832dc1d606dc1dbd83083601c1fab0").expect("Failed to decode key");
    let fixed_input = hex::decode("7738821d9685a8840b99d54442674fa9844ea966c235117f208ef7ee783e13322e8354046b4941f7cc2aaf43893f79188f19af3648a240e13b0285e6").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 160 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode("44b6a5c77f2b5ab65e8d513aee2eafda64923fdd")
        .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_before_fixed_32_bits_320_bit_output() {
    let key = hex::decode("f5b30bd08f8aaab4ab01d685bed62bea").expect("Failed to decode key");
    let fixed_input = hex::decode("640913e9f9912cda1d664a596adcba75524f549852613bb4fd02eabff3525a4780a09c1b0252843d709820445cd92f4cabccccd39acedbe1dc317870").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "6a0c9d6418fd60cc361576c806bccd0801a4b29ab8809c61f6b5a3315777aba0b238231342575b69",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_after_fixed_8_bits_128_bit_output() {
    let key = hex::decode("e61a51e1633e7d0de704dcebbd8f962f").expect("Failed to decode key");
    let fixed_input = hex::decode("5eef88f8cb188e63e08e23c957ee424a3345da88400c567548b57693931a847501f8e1bce1c37a09ef8c6e2ad553dd0f603b52cc6d4e4cbb76eb6c8f").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 8 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 128 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("63a5647d0fe69d21fc420b1a8ce34cc1").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_after_fixed_8_bits_256_bit_output() {
    let key = hex::decode("df2e41df668c7373b02f469bbce53279").expect("Failed to decode key");
    let fixed_input = hex::decode("e52c39ed54fac21c2fabd37f4b25c52d2335c5f77bdbc879a1ef75a1562c29e49b35bf582e37cdaf8d275b4279d1e295daf845f34c6d6c7c6a4e7db1").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 8 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 256 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("94d22ac548d86128918941bacbf88030104a750310c9b4205bae8b0ab6b25b42")
            .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_after_fixed_8_bits_160_bit_output() {
    let key = hex::decode("7dc0388f4cc082c1664c5d1679666c9f").expect("Failed to decode key");
    let fixed_input = hex::decode("053a6b087f3e225e4ea228e0e6bc14ea409737fd97ffa0cf841d8121769c01e5ddc43b3b946cbf083e00a3ca79d824b3728edede6f8a3a70ab40fb5c").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 8 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 160 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode("ee912df1fbac69543e5166889fd5f92af8a4dad1")
        .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_after_fixed_8_bits_320_bit_output() {
    let key = hex::decode("70a0f2fe78e939e88dd3dc49d3b759cb").expect("Failed to decode key");
    let fixed_input = hex::decode("8f5a79424b1ed8fdb67b5257998910d0ce9405235f5540c343e36613898016078826105e2e007d8395232ccbbe27d6ea3ab190dd62531ca9660e6377").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 8 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "efde3528b7d4a87c73ed78688c1783552b8be4a4dcfbeeeecb7f6fd2bd6f36d9a6b707cd6270643a",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_after_fixed_16_bits_128_bit_output() {
    let key = hex::decode("9686d328d5e02709307a252de3e128ce").expect("Failed to decode key");
    let fixed_input = hex::decode("ce89f996898d52069c9639cc4c59e93c0603738c6c8a0e4cc6f416381288eff07a787bd8d462eba0000d680b03f7328b7fc54e0bb5470d37cfdcaf2c").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 16 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 128 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("86f79c13188e073ab39223ae6800f747").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_after_fixed_16_bits_256_bit_output() {
    let key = hex::decode("bc5decf96f60ecb43437119e2a47a11a").expect("Failed to decode key");
    let fixed_input = hex::decode("f5c39f37fa7ff80bf9afaae589480fae4c50945674b035e1e47a39052de63b53ce9fe5d95675529d5974bb934fc24132ce0e56c8a1a8b332f5283b8d").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 16 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 256 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("2770585d5f4c3e34828564ae47610ec9e29627d4ca38dd9532aab045fe98c2f4")
            .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_after_fixed_16_bits_160_bit_output() {
    let key = hex::decode("4fa5b5b789ae8cbbc86eb3561b463741").expect("Failed to decode key");
    let fixed_input = hex::decode("d8dadd3d49e605b97417577996886ce80b02008334097404359e6563f0791b4078fa125ca7f750b60d2b570f0ce83ca46f6f475ff9f079e271102a8c").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 16 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 160 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode("5e815e422c31c6344ac50316fee65625c119504b")
        .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_after_fixed_16_bits_320_bit_output() {
    let key = hex::decode("632be06e38d3a8f24b59f862b459617a").expect("Failed to decode key");
    let fixed_input = hex::decode("c3370616ed72e006efa300dc584b3c6d441f8134299d433a8a0243e588613199b07ebf76aee6b0c2c46d04e9ad534c2423e5ef2151361e9951c8f839").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 16 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "fa70d41c5af46bb97708d4ed7f7eb9b650605a6540ac21d6bfb82494d6b793f9e2e2b9c6e99025ab",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_after_fixed_24_bits_128_bit_output() {
    let key = hex::decode("2353e3b831f4959c8340bdb892f1cbc4").expect("Failed to decode key");
    let fixed_input = hex::decode("4d77455c38180eec272c959b1967a554059963a191772b597f0461e5977a253827c57a66eb1606841c4c347896d5a787699a5ac6aea67021571e99c7").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 24 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 128 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("beb04b050dfb0e1d247245d3b16c33e6").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_after_fixed_24_bits_256_bit_output() {
    let key = hex::decode("367ace58251a12a40ee075aa65261575").expect("Failed to decode key");
    let fixed_input = hex::decode("735c4f0d1a157e238ad35e0f8cf2f0abc279329c93771ba2194a260625a87ae6cced85f3ca3f29b6e02e75028f5ade326d670e4924dca201d282e5ac").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 24 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 256 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("c16177233806c9fa28ac753166e66b8763db1f7854e355b742c19371fd2bbc80")
            .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_after_fixed_24_bits_160_bit_output() {
    let key = hex::decode("d9f318fcf640561ae80bc2b5bcbc702f").expect("Failed to decode key");
    let fixed_input = hex::decode("3903bd444aced19b8e2f5cb23ecd1c4695e64ec21c0dabb984b790fe8faab953c3de3be7abc17a3b7ecfe4e6a524c9b76fe8e04f03e5b3a88946eea8").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 24 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 160 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode("bf2a16292b5bc9186975faf653601048f181b991")
        .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_after_fixed_24_bits_320_bit_output() {
    let key = hex::decode("9bf9004b3e145c0c107a45815862d04a").expect("Failed to decode key");
    let fixed_input = hex::decode("daddb94d1b34c7c3a4f640a6792aacd4da310698c3866dc2d68fb5d31a15d3025c03026bbeac267bd78110c955e575b4b6ae126b12624fe7deb46a11").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 24 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "f0b18a165e22e8d264e666c27a20d8dc61a0e6684bcef8ca3911cc26aa0810351ffe39ba28e7810c",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_after_fixed_32_bits_128_bit_output() {
    let key = hex::decode("489875384bb0ea0e93e8472799b12fbb").expect("Failed to decode key");
    let fixed_input = hex::decode("c23ab8a611cb7f64546672048531fb39c869c2000d42a2477683d668edb50f52d41e44699ff94ecce019c7d6c27c1d202e9c4570b59abf609fb104e1").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 128 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("f87e4b09cfe7321148c830ed1a917201").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_after_fixed_32_bits_256_bit_output() {
    let key = hex::decode("24e517d4ac417737235b6efc9afced82").expect("Failed to decode key");
    let fixed_input = hex::decode("e9bb4b414fd4de817e78ef322e4e180956cb9be6c4ed25822bccb0e514aef084f87655108964e3452c00f9ab2dd8dd78333f51724383fe6cabbd015b").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 256 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("c6043c6b1bd81ea074a1b12351b5e3c46857c2886574b79adb94159461474664")
            .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_after_fixed_32_bits_160_bit_output() {
    let key = hex::decode("e5657b0c7100de6b964fbeda0b63cdab").expect("Failed to decode key");
    let fixed_input = hex::decode("a14e6b5c5eb18d464fee10dc7e2de17ff223e23967836d0fb3e6f41011003fb0947dcce2381d6defae390f0459635d1fa63b7e0afdee0a37f1e6065c").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 160 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode("90c3c6bddb960602a4f46d0730ea719ab313e6bc")
        .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_after_fixed_32_bits_320_bit_output() {
    let key = hex::decode("27ec9481ffb373b40c2cbb55abf83b99").expect("Failed to decode key");
    let fixed_input = hex::decode("8d0ae4d224d77c9b7eed07b21753e0d8d4dc57d1653d8ed57450a02f3d32ce13e6cd750918101679931428c94d7ad54a9de0ceae7a484545b1f34248").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "6f06740be953cd335ae7eacfc0d8c09d41fd27419eb2306f1d81b087d77f634aa05de7534bc1e564",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_middle_fixed_8_bits_128_bit_output() {
    let key = hex::decode("f8844ba943586c432a3651f23850bdd4").expect("Failed to decode key");
    let fixed_input = hex::decode("170b43391c09e65f9672c01d9743767ce9b96f48096e96a0041f3f9ca7ee8703606ed794ba67b5132afe0f83dd1df733e57cdea6e0549413fc2a26d0").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 8 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 128 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("8dfc0cc6a66631351f09c625b6cc4bf0").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_middle_fixed_8_bits_256_bit_output() {
    let key = hex::decode("81af08477372f38c56e127acd600e24c").expect("Failed to decode key");
    let fixed_input = hex::decode("65d89a710994ab00ec66588de78560018eec589fc8c86f2d6fcc18783bc793e7c7c467084f59b6c122407695eff18ea2f443cb9c0a61af46da34fa74").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 8 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 256 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("5eb6bdbf35322fef20b6a4e30e1a3f2b4e86bcb002d87e9e1fdea554ffe3077d")
            .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_middle_fixed_8_bits_160_bit_output() {
    let key = hex::decode("3cc8c5621a795052f288e5464da7010f").expect("Failed to decode key");
    let fixed_input = hex::decode("7dac5dec921ed40df8ef64318fea097c8df883ec19bfc2c7380a2d3ed0da2136658eb215315755f1a796ca4c47d60f89954a0b39075dc2d52587434c").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 8 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 160 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode("64a260623acce683cceee7c997653d5e14c18e67")
        .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_middle_fixed_8_bits_320_bit_output() {
    let key = hex::decode("7b4572da1398a381f603e5e93d5154b2").expect("Failed to decode key");
    let fixed_input = hex::decode("aede23e7e90f2f343134bf4766cb67bad52c5e0170a9ca07fb23e36cc52dcc472d8fb95ec65a3facca20dc37a148f6a2a42a24489f40f6588b9d5c0f").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 8 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "3452be5f7062537ec48796db84f6f6455abee41868689a379fbf46954fdc9a367d1cf4b9cd9009b0",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_middle_fixed_16_bits_128_bit_output() {
    let key = hex::decode("a099818fa4d0739bb1bdd6940aceeb06").expect("Failed to decode key");
    let fixed_input = hex::decode("990c08c8f4ca1c901b586b4510011471f2ee86a739e81faf1b2cc375b68946704e473738f938bfa3356405fb616ef0c154a8ed43407b5f4148e23dd3").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 16 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 128 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("9ba2519bec604ae5709bc4085cbff9d3").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_middle_fixed_16_bits_256_bit_output() {
    let key = hex::decode("c99913ed63370263287c765cb3f6f857").expect("Failed to decode key");
    let fixed_input = hex::decode("6a7f6475f8ea06af86cbd4c8325a5d27f9be229bd7933ad51cb21fac9499b94c246f6f7cb83af4a58f88a958566199ee73ad5c6988f575d80f186a2b").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 16 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 256 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("f83a7e1024baed943bcc531acc9bc638c9f787cec53b8b4fae186590e8c942a4")
            .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_middle_fixed_16_bits_160_bit_output() {
    let key = hex::decode("36b25adaa979448901027ee65ca0fb81").expect("Failed to decode key");
    let fixed_input = hex::decode("83f18ffafa09566634523207f64854a7eac6d2d093205eeab30ef0370784af27030bf9dd8e4e25dc69d6feddd69c1ad5d66d1f326c4e43403d1c655b").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 16 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 160 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode("70f1031014c0cc1f8fc5860eb245c0fb21e3001d")
        .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_middle_fixed_16_bits_320_bit_output() {
    let key = hex::decode("de4f1d647df9f457721bca7fb5b5232d").expect("Failed to decode key");
    let fixed_input = hex::decode("28c43f550b8db64b6b1579cc5f6f184714b5a23a6df1b44f914f87c42aa88e9eb2e0a1f0e28d4457d4b345a59e922f7cc2ec22611b14ab47da94d22c").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 16 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "2c848e8317d3faabda851f22dcd5ba8ab8a0ecfd342b28c0f33b982cae93235efda913cca2854c75",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_middle_fixed_24_bits_128_bit_output() {
    let key = hex::decode("11f7f0b9083ad914b6e58bfc267c6296").expect("Failed to decode key");
    let fixed_input = hex::decode("29794a6e0e80e8cbd5735148e2f8330ad63a6ecc8ada76487f92c2ec5a64056df050df3c58eda2c0cedac3297281672e9d82ae17e5f1893b8fdcc784").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 24 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 128 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("e4635b28b3dc0be14e99a38fa016295b").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_middle_fixed_24_bits_256_bit_output() {
    let key = hex::decode("2f0a7c94b5d7a172b7f6072ffc460ab5").expect("Failed to decode key");
    let fixed_input = hex::decode("fdca023f2de06e41dcfd8c351394dc9ac1b406cfc34da48c061aeb5fc91a92c1fad25e39492afed7bbfb893d0ee8909b5130ff0ee46ff54309dac99e").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 24 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 256 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("86dfd5df1b3078ce7c665b62ab332ae40cc2558b8557427efa996ca0f9ca74e8")
            .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_middle_fixed_24_bits_160_bit_output() {
    let key = hex::decode("9ac88069fa82e2d46f1ecdf03f83231f").expect("Failed to decode key");
    let fixed_input = hex::decode("d45373fb8da0c4c818a90b544e7408759364ba8384af297aa8a34d549abb75bcf84ee57160067150058ca41441301b199fa75ad543294646b1c4182e").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 24 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 160 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode("0c34df2003aea7ebb3fd4f8c42ee3f4c5519d7bd")
        .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_middle_fixed_24_bits_320_bit_output() {
    let key = hex::decode("30dbe39c1cf412512231bbfa3d6d74d5").expect("Failed to decode key");
    let fixed_input = hex::decode("d33b947333fada16d891e605a48cd96784bee6c7dcf8ded83c218d37ba975a9ec6df9a08afd8828ee6bf691b9025e2e0f6deca9cb2e63dce81185105").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 24 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "9f3ae777b465ed8699e721a3c3642f15a4e01f6d4594071daf15d8e0b960e6ab95690c5b94f33460",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_middle_fixed_32_bits_128_bit_output() {
    let key = hex::decode("817526d4c8a724f5efb4c336456be7a8").expect("Failed to decode key");
    let fixed_input = hex::decode("40f8d8e467ada581c8179efb9070b44b3e08e605f532d13c677a1889958c0e90398e143d1253766999401d4097af2739d7798b615467c2b38c21f8cf").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 128 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("24b82a08fba5f06eff021e7a54aa9936").expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_middle_fixed_32_bits_256_bit_output() {
    let key = hex::decode("fcc9d5c417e14387fa16e1f4a42a756c").expect("Failed to decode key");
    let fixed_input = hex::decode("f4e53cfe4baf41939b544bbdf315aea8bd9bf5885e823b3cacb9250bf9fc4c5784629b96bd40f3e2f2c251f76ea8b10e22bf08c11654a44b183d82c5").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 256 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result =
        hex::decode("82bd77c2e801192b8399fe8750ba0f0c72aa4d5d50502c37ce7b2bbc992d9fde")
            .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_middle_fixed_32_bits_160_bit_output() {
    let key = hex::decode("0d09a23b6a2fb40d1bfd2aa1780b6266").expect("Failed to decode key");
    let fixed_input = hex::decode("dc1eb9074a2dd8e0b45228b1a699988dc327b61b78fb6fe58fbdb7ebb12c9725fad6b3dcc2de0e4e784cb84cdc2bc96fb83277eda36af66c0b24b932").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 160 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode("8fab06aebcb6f233162b4dc9cd5ad71094090b33")
        .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_128_middle_fixed_32_bits_320_bit_output() {
    let key = hex::decode("01a39a51b93a0e063138e702fee4655a").expect("Failed to decode key");
    let fixed_input = hex::decode("9a43899394bac7860b0473a2f1bb55289247a40dc6f5653f81f22a06ed6ecf214419419a93bb0df46304e42575ae4ea76a4262385b367b5ed4f4b1f1").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_128_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "1b4338224a55b54f68fd30777aba5fc5c8970c2503f1f30155a59b1b2b21c652acf259aea03453b9",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_192_before_fixed_32_bits_320_bit_output() {
    let key = hex::decode("d64c598436507f4d05d7ebe780092996f281901dc9c8612f")
        .expect("Failed to decode key");
    let fixed_input = hex::decode("0ea737cfca2560856917f3a2ff5e2175930d0719bba85a9c8d8cb311a0a1b8caf8ffe03e9a86ab17046670011c9fec5c5cd697d9cd931f615cdfe649").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_192_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "3c26968bd3997c653f79bb725c36d784b590d18a64678cf312abe8a57b2891c27282e37b6a49cd73",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_192_after_fixed_32_bits_320_bit_output() {
    let key = hex::decode("5a1ea452525f99f61bf2f2e680a5856b3263bdcfe4c3f8ba")
        .expect("Failed to decode key");
    let fixed_input = hex::decode("f93a88be1591168a677030e5d2b61f220d959722b7292d65a25c43f0c99db4bdc76248be329ee31052d216295961d0fae59ebf46939129324639dac6").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_192_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "32df46ca9aae3c0c71681d667c8bf7b454f758e2797391a959c43ff5695399ab6f2e7ce44663db53",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_192_middle_fixed_32_bits_320_bit_output() {
    let key = hex::decode("9bb4cb7e2eac5b5b9bae563c786bde0fff78cc7b2c1194ed")
        .expect("Failed to decode key");
    let fixed_input = hex::decode("60c8978c7ae2dcde90dcd46b0eab51fe59fcd230d792c64102d5b9e2f4943653a114232655a5d27c9ab8e476647f4c9a15209144a2acccc05fc9efb4").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_192_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "0dcde501b66c3fe8b8576a7661ac0622f308a091b5cb933643c49814608792ebe37586ee364339c5",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_256_before_fixed_32_bits_320_bit_output() {
    let key = hex::decode("9f74dcc44cff4bdb0d45bf487063613d5d1d8a298b6ec856709bd5d7b335c27d")
        .expect("Failed to decode key");
    let fixed_input = hex::decode("fe19857b0bae929e40ad53049f7c3a1e544e492ad2ddee372daa9e90a50d706088c18abca2429a809c9d7f46a5a1db738c466014b4727ca7afe2da1e").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_256_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::BeforeFixedInput,
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "dbefa67eabcaec5870cfce311944cac936914708b95c10ec137ddc4ed8b9cae4304edfac35aaa536",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_256_after_fixed_32_bits_320_bit_output() {
    let key = hex::decode("2ea718d0549220cec6de30143633d50250b13b8240fae23ffb08e1e7cbff7c9e")
        .expect("Failed to decode key");
    let fixed_input = hex::decode("29f46de7ad78b86c4af87182794331004ae17ac3681a1a6c6afa1f5e1e4f357df23721464b0533fc273be0d4faf6adeae9a053564cfc562c6d5b9964").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_256_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::AfterFixedInput,
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "849ca0ca060e9f56446087613319390c604fb704c6bafa72e5374ba90da24f6cbc4be09c12612201",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}

#[test]
fn cmac_aes_256_middle_fixed_32_bits_320_bit_output() {
    let key = hex::decode("174bcd4b458adcddabe9985020e044446ba6f47e3c5e11d6883529cb29615f40")
        .expect("Failed to decode key");
    let fixed_input = hex::decode("94f8d8f2dbeac24ecdd978d75e523b015d77020b717baedc09ab7ac1102dd6b8562e064e47124c4a486a97b8bca3a76f21f4d1ed46af2292baca5f72").expect("Failed to decode fixed input");
    let key = AesCmacKey::new(key.as_slice()).expect("Failed to load AES Cmac Key");
    let mut prf = AesCmac::new(Cipher::aes_256_cbc());

    let mode = KDFMode::CounterMode(CounterMode { counter_length: 32 });
    let input = InputType::FixedInput(FixedInput {
        fixed_input: fixed_input.as_slice(),
        counter_location: CounterLocation::MiddleOfFixedInput(50),
    });

    let mut output = vec![0; 320 / 8];

    kbkdf(&mode, &input, &key, &mut prf, output.as_mut_slice()).expect("Failed to perform KBKDF");

    let expected_result = hex::decode(
        "8f2c0cebe83839fc0064ce02c2210a6d533704087427c92296958c05c9c5b552678e7d43ab188035",
    )
    .expect("Failed to decode expected output");

    assert_eq!(output, expected_result);
}
