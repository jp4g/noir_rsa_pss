use bignum::{params::BigNumParams, RuntimeBigNum};
use rsa::{rsa::verify_sha256_pss, types::RBN2048};

// Examples of the signature limbs, modulus, and redc params can be generated via
// ../../signature_gen/main.rs.
// Note: technically, the `signature` could've been passed into `main` directly,
// for a much cleaner interface.
// The reason we chose this more verbose approach here, was to reduce the amount of
// data to generate for the Prover.toml file.
fn main(
    hash: [u8; 32],
    signature_limbs: [Field; 18],
    modulus_limbs: [Field; 18],
    redc_limbs: [Field; 18],
) {
    let has_multiplicative_inverse = false;
    let params: BigNumParams<18, 2048> =
        BigNumParams::new(has_multiplicative_inverse, modulus_limbs, redc_limbs);

    let signature: RBN2048 = RBN2048::from_array(params, signature_limbs);

    assert(verify_sha256_pss(hash, signature, 2048));
}

#[test]
fn test_main() {
    // Output of `cargo run -- --msg "hello world"` in the `signature_gen` directory
    // Create runtime params:
    let modulus_limbs = [
        0x83e879145bffccbe4d783abeca8999,
        0xb7d9868f5b915b43f6c6a8193a1a4f,
        0x67f95badedef107f0998ab3d52961e,
        0x7dcc9780ac8d71c6b49bbfeca25f0,
        0xf9fdced289a3d4f62830681be65b50,
        0x986aa8fe98888e9f609af97515b036,
        0xd494bc65f4608849a6ed8cf5cb82ed,
        0x18ca508b8353e676387d22667e4adb,
        0x9d3fcb816b4763099ccbb7416a7ad,
        0xcfd89fee1ffcfa5f2243c92e3908b7,
        0xcaf320fbb34158238b41042f9c6386,
        0xb3df0cd5dee269ecec61b342880c59,
        0x2134236dc67b59df001cac48181625,
        0x536d424ce3dcaf2b3c15eba3ceb98,
        0x7c6532647de2f025c4245c4a816ea9,
        0x1ca6b6ac38706f61dd460c53293c88,
        0x812b9256f612815edb22ec614a6c89,
        0xc9,
    ];
    let redc_limbs = [
        0x9ec08341171d384b92ed35848dac43,
        0xaa5e7059598102ad1d99f33e533781,
        0x894978a6e54a780efd6c579b74dd3f,
        0x9531219036eb346dc4d2f142d9aeb3,
        0x2d67220edac65500daea360896b937,
        0x72393de3ce76a185b8d5fe4efeb301,
        0x2e5a676dc2d3d971ead0a1a8127ff1,
        0xbb92e11f4b88fb1f478a8e5fcc8a63,
        0x978205931de77dc276cbffcfa9ab06,
        0x3f0074f27a70de9b87b38923c5d26f,
        0x315d3964500ad7da70267bebb13aed,
        0xee04558c06aced97c3375cb93ae624,
        0xcaf9c90ec5317baf27dabd3f3a6018,
        0x453a832dd0cf10c2e7669123ffdabe,
        0xc6c46372e3eda40f2582e2e9902867,
        0xcdb6b9ecb85a01524cbe4cee82a2c2,
        0xbbaa5920d526e092f29b41b1c629e1,
        0x1453,
    ];

    let signature_limbs = [
        0x2e3f7f3a3b7d89cbf680adcee4f039,
        0xcca286445a216e1c110416099710f3,
        0x0684d04d7773fbff2223360e314f47,
        0x1342e7d3f7cadd18ba5f0ed57b1e54,
        0xe5347fc80630780900cffe3d20cb7d,
        0xda578cadd719f2a38f505d54c46203,
        0x4a729fdd97383a0e32b5e8f671c833,
        0x810ea2ce9ace9bd072bd3b221c9b62,
        0xc565d6bff72c8501a729ecab2aee3b,
        0xe042b627c4e6b4cc6ab4ca0ababaaa,
        0x8e707750c71a4f9f0b9d9389b61826,
        0x850297f956c58dafb6bf4f7bb049fa,
        0x32c51e7454edae060725c509d9a48c,
        0xbe2f1df6227e67dc61e6ab82bc501f,
        0xea17c90cc7053bbb94ddfac6b1a405,
        0x6c6eaada9c24dfa1a476c3718f6735,
        0x0134b376c64ba2a79a086061573792,
        0x22,
    ];

    // let hash: [u8; 32] = dep::std::hash::sha256("hello world".as_bytes());
    // hash of the jwt
    let hash: [u8; 32] = [
        190, 196, 184, 50, 102, 89, 57, 43, 211, 245, 140, 168, 170, 163, 80, 128, 25, 139, 25, 68,
        239, 215, 154, 164, 148, 234, 47, 212, 6, 140, 157, 110,
    ];

    main(hash, signature_limbs, modulus_limbs, redc_limbs);
}
