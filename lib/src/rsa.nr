use dep::bignum::{params::BigNumParams, RuntimeBigNum};

/**
 * @brief Compare a recovered byte hash from an RSA signature to the original message hash
 * @details Taken from https://github.com/richardliang/noir-rsa
 **/
fn compare_signature_sha256<let N: u32>(padded_sha256_hash: [u8; N], msg_hash: [u8; 32]) -> bool {
    // Get length of sig (e.g. 1048 = 128 bytes, 2048 = 256 bytes)
    // NOTE: Assume MAX_BYTES < 2^32 bit number. MAX_BYTES of 259 > 2^8 bits so need to cast it to u32
    for i in 0..32 {
        // Padded hash is reversed
        assert(padded_sha256_hash[31 - i] == msg_hash[i]);
    }

    let hash_prefix: [u8; 19] =
        [32, 4, 0, 5, 1, 2, 4, 3, 101, 1, 72, 134, 96, 9, 6, 13, 48, 49, 48];

    for i in 32..51 {
        assert(hash_prefix[i - 32] == padded_sha256_hash[i]);
    }

    assert(padded_sha256_hash[51] == 0);

    // Sub 32 bytes for hash, 19 bytes for prefix, 1 byte for 0, 1 byte for 1, 1 byte for 0
    let ps_len = N - 54;
    for i in 52..N {
        if i < 52 + ps_len {
            // PS padding which depends on RSA modulus / sig length. 1024 bits = 128 bytes = 128 - 54 = 74 bytes of 0xFF padding
            assert(padded_sha256_hash[i] == 255);
        } else if i == 52 + ps_len {
            // Pad 0x01
            assert(padded_sha256_hash[i] == 1);
        } else if i == 53 + ps_len {
            // 0x00
            assert(padded_sha256_hash[i] == 0);
        } else {
            // Padded with 0 until MAX_BYTES
            assert(padded_sha256_hash[i] == 0);
        }
    }

    true
}

/**
 * @brief Verify an RSA signature generated via the pkcs1v15 signature scheme.
 * @note The `exponent` can be either 65537 or 3 (i.e. the most common values in use for RSA)
 * Rough cost: 2,048 bit RSA: 26,888 gates per verification
 *             1,024 bit RSA: 11,983 gates per verification
 * A circuit that verifies 1 signature (and does nothing else) will cost ~32k due to initialization costs of lookup tables
 **/
pub fn verify_sha256_pkcs1v15<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 32],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    exponent: u32,
) -> bool {
    assert((exponent == 3) | (exponent == 65537), "Exponent must be 65537 or 3");
    let mut exponentiated = sig * sig; // sig^2
    if exponent == 65537 {
        // e = 65537 = 1 0000 0000 0000 0001
        exponentiated = exponentiated * exponentiated; // sig^4
        exponentiated = exponentiated * exponentiated; // sig^8
        exponentiated = exponentiated * exponentiated; // sig^16
        exponentiated = exponentiated * exponentiated; // sig^32
        exponentiated = exponentiated * exponentiated; // sig^64
        exponentiated = exponentiated * exponentiated; // sig^128
        exponentiated = exponentiated * exponentiated; // sig^256
        exponentiated = exponentiated * exponentiated; // sig^512
        exponentiated = exponentiated * exponentiated; // sig^1024
        exponentiated = exponentiated * exponentiated; // sig^2048
        exponentiated = exponentiated * exponentiated; // sig^4096
        exponentiated = exponentiated * exponentiated; // sig^8192
        exponentiated = exponentiated * exponentiated; // sig^16384
        exponentiated = exponentiated * exponentiated; // sig^32768
        exponentiated = exponentiated * exponentiated; // sig^65536
    }
    // otherwise, e = 3 = 11
    exponentiated = exponentiated * sig; // either sig^2 * sig = sig^3 or sig^65536 * sig = sig^65537
    let mut padded_sha256_hash_bytes: [u8; (ModBits + 7) / 8] = exponentiated.to_le_bytes();
    compare_signature_sha256(padded_sha256_hash_bytes, msg_hash)
}

pub fn verify_sha256_pss<let NumLimbs: u32, let ModBits: u32>(
    msg_hash: [u8; 32],
    sig: RuntimeBigNum<NumLimbs, ModBits>,
    key_size: u32,
) -> bool {
    // Exponentiate the signature assuming e = 65537
    let mut exponentiated = sig * sig;
    for _ in 0..15 {
        exponentiated = exponentiated * exponentiated;
    }
    exponentiated = exponentiated * sig;

    // Convert the exponentiated signature to a byte array and reverse it to
    // get it in big endian order, which is much easier to work with for
    // the rest of the verification process
    let em: [u8; ModBits / 8] = reverse_array(exponentiated.to_le_bytes());

    // The modulus size in bits minus 1
    let em_bits = key_size - 1;
    // The actual length of the encoded message without any of the leftmost 0s
    let em_len = (em_bits + 7) / 8;
    // The length of the modulus in bytes
    let key_len = (key_size + 7) / 8;
    let h_len = 32;
    let s_len = 32;

    // Check if emLen < hLen + sLen + 2
    assert(em_len >= h_len + s_len + 2);

    // Check if eM ends with 0xBC
    assert_eq(em[em.len() - 1], 0xBC);

    let db_mask_len = em_len - h_len - 1;
    // In some rare cases, em_len is not equal to key_len (e.g. 1025 bit RSA)
    // In this case, we'll have a leading zero byte in em that we need to ignore
    // c.f. https://github.com/RustCrypto/RSA/blob/aeedb5adf5297892fcb9e11f7c0f6c0157005c58/src/algorithms/pss.rs#L242
    let offset = key_len - em_len;
    // As the hash is 32 bytes and we also remove the 0xBC at the end, we have up to NumBytes - 33 bytes left for DB
    // For example, for 2048 bit RSA (i.e. 256 bytes), we have 256 - 33 = 223 bytes left for DB
    // and for 1024 bit RSA (i.e. 128 bytes), we have 128 - 33 = 95 bytes left for DB
    let masked_db: [u8; (ModBits / 8) - 33] = get_array_slice(em, offset, db_mask_len + offset);
    let h = get_array_slice(em, db_mask_len + offset, em.len() - 1);

    // Make sure the 8 * em_len - em_bits leftmost bits are 0
    // c.f. https://github.com/RustCrypto/RSA/blob/aeedb5adf5297892fcb9e11f7c0f6c0157005c58/src/algorithms/pss.rs#L205
    let bits_to_mask = 8 - (8 * em_len - em_bits);
    let mask_value = pow(2, bits_to_mask as u32);
    assert_eq(masked_db[0] as u32 / mask_value, 0);

    // Generate dbMask using MGF1
    let db_mask: [u8; (ModBits / 8) - 33] = mgf1_sha256(h);

    // Compute DB = maskedDB xor dbMask
    let mut db = [0 as u8; (ModBits / 8) - 33];
    for i in 0..db_mask_len {
        db[i] = masked_db[i] ^ db_mask[i];
    }

    // Set leftmost byte of DB to 0
    db[0] = 0;

    // Check if the leftmost octets of DB are zero
    for i in 0..(em_len - h_len - s_len - 2) {
        assert_eq(db[i], 0);
    }

    // Check if the octet at position emLen - hLen - sLen - 2 is 1
    assert_eq(db[em_len - h_len - s_len - 2], 1);

    // Extract salt
    let salt: [u8; 32] = get_array_slice(db, db_mask_len - s_len, db_mask_len);

    // Construct M'
    // M' = (0x)00 00 00 00 00 00 00 00 || msg_hash || salt
    let mut m_prime = [0 as u8; 72]; // 8 + h_len + s_len
    for i in 8..40 {
        m_prime[i] = msg_hash[i - 8];
    }
    for i in 40..72 {
        m_prime[i] = salt[i - 40];
    }

    // Compute H'
    let h_prime = dep::std::hash::sha256(m_prime);

    // Compare H and H'
    h == h_prime
}

fn reverse_array<let N: u32>(array: [u8; N]) -> [u8; N] {
    let mut reversed = [0 as u8; N];
    for i in 0..N {
        reversed[i] = array[N - i - 1];
    }
    reversed
}

fn get_array_slice<let N: u32, let M: u32>(array: [u8; N], start: u32, end: u32) -> [u8; M] {
    assert(end - start <= M);
    let mut slice = [0 as u8; M];
    for i in 0..M {
        if i < end - start {
            slice[i] = array[start + i];
        }
    }
    slice
}

fn pow(base: u32, exp: u32) -> u32 {
    let mut result = 1;
    for _ in 0..exp {
        result *= base;
    }
    result
}

global HASH_LEN: u32 = 32;

/**
 * @brief Generate a mask from a seed using the MGF1 algorithm with SHA256 as the hash function
 **/
fn mgf1_sha256<let SEED_LEN: u32, let MASK_LEN: u32>(seed: [u8; SEED_LEN]) -> [u8; MASK_LEN] {
    // MASK_LEN must be less than 2^32 * HASH_LEN
    std::field::bn254::assert_lt(MASK_LEN as Field, 0xffffffff * HASH_LEN as Field + 1);

    // HASH_LEN bytes are added at each iteration and there is at least 1 iteration
    // so if HASH_LEN is not enough to fill MASK_LEN bytes in one iteration,
    // another one is required and so on.
    let iterations = (MASK_LEN / HASH_LEN) + 1;

    let mut mask: [u8; MASK_LEN] = [0; MASK_LEN];
    let mut hashed: [u8; HASH_LEN] = [0; HASH_LEN];

    for i in 0..iterations {
        let mut block: [u8; SEED_LEN + 4] = [0; SEED_LEN + 4];

        // Copy seed to block
        for j in 0..SEED_LEN {
            block[j] = seed[j];
        }

        // Add counter to block
        let counter_bytes: [u8; 4] = (i as Field).to_be_bytes();
        for j in 0..4 {
            block[SEED_LEN + j] = counter_bytes[j];
        }

        // Hash the block
        // First SEED_LEN bytes are the seed, next 4 bytes are the counter
        hashed = dep::std::hash::sha256_var(block, SEED_LEN as u64 + 4);

        // Copy hashed output to mask
        for j in 0..HASH_LEN {
            if i * HASH_LEN + j < MASK_LEN {
                mask[i * HASH_LEN + j] = hashed[j];
            }
        }
    }

    mask
}

#[test]
fn test_verify_sha256_pkcs1v15_1024() {
    // Output of `cargo run -- --msg "hello world! test#123" --bits 1024` in the `signature_gen` directory
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("hello world! test#123".as_bytes());
    assert(
        sha256_hash
            == [
                220, 155, 229, 143, 122, 133, 55, 215, 75, 44, 132, 111, 57, 33, 248, 84, 213, 170,
                193, 96, 253, 57, 124, 13, 251, 42, 92, 147, 105, 172, 233, 85,
            ],
    );

    let params: BigNumParams<9, 1024> = BigNumParams::new(
        false,
        [
            0xab238ad9cb37979a43aefbf10be8fb,
            0x31347febe45fe8c2dac1dd30900704,
            0xa5a9a6b9cd0cc2b9d13bbd4e068263,
            0x5eac6390f7873fe97ff9bb14a173ea,
            0xbc41f700c91fd733a2c63177bbdbd4,
            0x41442bd58769a3595b659a2ec9c6be,
            0x4ddc91395f330382aa2e2d3fbe147,
            0x3d008ff255a0bc71c7887f5728ba1,
            0xb640c3a8f511c64e,
        ],
        [
            0x5d53d2634c6a0918266043968ce263,
            0x5dd4be3dce0323a492ee9340aec4db,
            0xf82d0e2e5c8319f01a460c72c01854,
            0x236e6fc6e62e8a1d522acda5fb3892,
            0xdaf755619d66e580901aa224d03174,
            0x8366291616480e7e1f202dbcedda87,
            0x40ba1202537d1e94561ccc05265586,
            0x69b993d857ba89ea5de9822aeb4b93,
            0x167968c0000761a273,
        ],
    );

    let signature: RuntimeBigNum<9, 1024> = RuntimeBigNum {
        params,
        limbs: [
            0xc3850e84ea02da3f028ff422f4d6a9,
            0x9761f0bd9021f76d45c60df0670a19,
            0xc1ede421a43607ab623ed4d5a17fc8,
            0x86197b4315206f4d53200b42555831,
            0xe95783b69db28c26a83706f39d04cd,
            0x18b178dc1a9ec76fb22b57e4dfa703,
            0xdd0e19cd5a09ab48e7af4d0e3470e3,
            0x10004dfab1cf91304e80e6baa4dfc7,
            0x241c3fd77b90adef,
        ],
    };

    assert(verify_sha256_pkcs1v15(sha256_hash, signature, 65537));
}

#[test]
fn test_verify_sha256_pkcs1v15_2048() {
    // Output of `cargo run -- --msg "Hello World! This is Noir-RSA"` in the `signature_gen` directory
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
    assert(
        sha256_hash
            == [
                91, 207, 46, 60, 22, 153, 217, 144, 2, 127, 224, 143, 181, 45, 32, 120, 122, 131,
                166, 79, 166, 183, 43, 158, 116, 105, 73, 207, 196, 77, 33, 5,
            ],
    );

    let params: BigNumParams<18, 2048> = BigNumParams::new(
        false,
        [
            0x8d5e7d9daedd6cfd1c9bdf0227e05b,
            0xbfb937fc4d3cf02cc0af780f3cab44,
            0xd20637ef7adcf5d238ee87bccc9bca,
            0xb9db4f2663108e2f8b673f7612ae8b,
            0x85f894ef669b36bfd3d86b0a28873,
            0xdcc70e1884e38b8229cce3b884121d,
            0x35488d1138e0b03e1676f7f5d8a5b3,
            0xe1a97820e7dcbb4eab35c9b71bb273,
            0x97d19eb3c63249ddbfcff915863f54,
            0x3a78c7af6da0f6af0d67b1ca4b6065,
            0xd7a3c433c020f624821e5e678c7d69,
            0x52d5b53240feae82ffea3d2a3d9b09,
            0xb8aad5e19e2163f68997c6fdd71906,
            0x5db432d06e8b0bf59511100c7894e2,
            0xadc0bbc4c54da10d1cc88438ea3127,
            0xece1cf6a1501109cd2734d5893c8d9,
            0x7196b90acdf06c31b1288064fd0c27,
            0xc8,
        ],
        [
            0x1b1deccf4dbde852c34a5d6908a0f,
            0xbc9e5bdab22f023fbcca58692bccf5,
            0x1f65439685623e45396ff55751c3bf,
            0x2b6ad2c5f8e3aac15d0ccbab816bfa,
            0x5ca2e8e3048243c16c708a8030ab0d,
            0x30079bfeb1fa51e5501581173ca19c,
            0xff8d5f6bea485fdcc2716327f69ab4,
            0x36b599d81589416b5b5f037986b999,
            0x75612e34a4ff29f0a19a7823512f58,
            0x288b6897929b54c3b26a5faa07c00f,
            0x4b5675fa13ab7444f1f047d3eb1bbe,
            0x6ba0ac610ef9f267ab30fe25bb1c84,
            0xa386b48ee03168d5cea3ecb9dc901f,
            0xacf1a01f7dba44e050c976142fb1f6,
            0x97a63b5cb7efc60d3502946aec63cf,
            0x12cc1d5cab10a1e9e2398d29b9e3ef,
            0x4635cf25c66e76bba8034df46204fb,
            0x146f,
        ],
    );

    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum {
        params,
        limbs: [
            0xad29e07d16a278de49a371b9760a27,
            0x86311920cc0e17a3c20cdff4c56dbb,
            0x863556c6c5247dd83668dd825716ae,
            0xc247c960945f4485b46c33b87425ca,
            0x7326463c5c4cd5b08e21b938d9ed9a,
            0x4f89fe0c82da08a0259eddb34d0da1,
            0x43a74e76d4e1bd2666f1591889af0d,
            0x240f7b80f0ff29f4253ee3019f832d,
            0xc6edd131fbaaf725fd423dac52b362,
            0x85f9732679242163e8afff44f6104d,
            0xd3c3bbcb1757013fd6fb80f31dd9a6,
            0x9008633f15df440e6df6d21ee585a2,
            0x324df3425ed256e283be5b6b761741,
            0xc60c1302929bd0e07caa4aeff4e8fd,
            0x600d804ff13ba8d0e1bc9508714212,
            0x50f7e75e5751d7edd61167027926be,
            0x0db41d39442023e1420a8a84fe81d9,
            0xab,
        ],
    };
    assert(verify_sha256_pkcs1v15(sha256_hash, signature, 65537));
}

#[test]
fn test_verify_sha256_pkcs1v15_2048_exponent_3() {
    // Output of `cargo run -- --msg "hello world" -e 3` in the `signature_gen` directory
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("hello world".as_bytes());
    assert(
        sha256_hash
            == [
                185, 77, 39, 185, 147, 77, 62, 8, 165, 46, 82, 215, 218, 125, 171, 250, 196, 132,
                239, 227, 122, 83, 128, 238, 144, 136, 247, 172, 226, 239, 205, 233,
            ],
    );

    let params: BigNumParams<18, 2048> = BigNumParams::new(
        false,
        [
            0xe40ee47801326543c8e84b85d567c1,
            0x5b54ea87f0ce29de1995697b0696fd,
            0x457078f8fdce68b437cac0970b2452,
            0x473ec776fee3731b6ab06e35875ddc,
            0x62dedd594e5f12c80c3ccb5791a6cd,
            0xecb934b9d8272c5e3a418145345499,
            0xd1af643b3d785470ed0c6cd633f706,
            0xb58a57b9e96eccbdfc7c17f0333d4,
            0x2ebd34b5039fc596504927c282c60d,
            0x3a44928a74f25fc1043bb37ce4dfa8,
            0x91448459f9617fac33a2816162ac9e,
            0x70cb910d9f3e1a78864640ec6c8240,
            0x9aed33f6b31f1c9de67248a98c180,
            0x7f1416e032c79488c94b311e87bd9c,
            0x7191b4ebb1b3fffa949fa48ed01e5,
            0x350a75cbaeca6bfdd71ca83cdbcae9,
            0xfb1d274fa207457c6814d42c09f9cf,
            0xd4,
        ],
        [
            0x803bf4d38110a7d37fdd05f590dee9,
            0xa68d317c933f37cab5ab4e7c00a3b9,
            0x476a05a536bf5f2aa1b8850146cba7,
            0xca297ea8b5528d91d4836ff27c30ab,
            0x75cf2eaab76eefa12bbd570f1aea9f,
            0x8f6a8ab877d9c5bcd98c37bdc5c2d3,
            0xd497db1f6ebe83decacaa647fabea6,
            0x686b27ca330e25e7a7cf197f6433ef,
            0xfde04d2225c8308b07580af0058a0f,
            0xa29fb69777c0e916976243b2b09855,
            0xf983592285852e7e1c2cb3ae968323,
            0x673608017f9f5acf67a01b73728d70,
            0xeeff82521c0bc432a05f4b7444fac0,
            0x85a89c4d229f60aaa3aa7ac7dac1e2,
            0xcfecff93bc9fbfe0d6dff6091f2db8,
            0xf20f047dcb224b4447bd098c07f8c2,
            0x554bb53cadeb3eaab911a189f90227,
            0x133b,
        ],
    );

    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum {
        params,
        limbs: [
            0xa250eff812c63eaaeaa3f04641c05f,
            0xecc09613cb8b289c1f37c8f92e6a05,
            0x2c0a0510058360c07af65d46f594fd,
            0x943d67513363d3de430c94a1dafe7c,
            0x511ec8e9b10bc6c6ff0d6c232ccf92,
            0x50ffd07b3c093b3f5fc027de847731,
            0xc268e1489449943fdafdf89ff168c3,
            0x0b8b7f9f49b492f78fda58d252f23a,
            0x491c6c4ef836a6a8730b7bf81e865e,
            0x8746c75fb079d014e419543f56d7f0,
            0x65804c417d6168a8bc0025d255cebf,
            0xf695e91b77890b8e3fd775fa56e627,
            0x5e90001c0218550f4083ae28025a2f,
            0x526bd4eff34f25f62a698f0470e0a6,
            0x7f224306a7d9daf536b1559434c6c6,
            0x88809f16fe1fcea3c87511d9319735,
            0x7694685fee0bfab4a9196b92ec6f2e,
            0xa7,
        ],
    };

    assert(verify_sha256_pkcs1v15(sha256_hash, signature, 3));
}

#[test]
fn test_mgf1_sha256() {
    let seed: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
    let expected_mask: [u8; 32] = [
        106, 93, 232, 46, 236, 203, 51, 228, 103, 104, 145, 29, 197, 74, 26, 194, 135, 200, 40, 232,
        179, 172, 220, 135, 51, 185, 209, 35, 194, 131, 176, 190,
    ];
    let mask: [u8; 32] = mgf1_sha256(seed);
    assert(mask == expected_mask);
}

#[test]
fn test_verify_sha256_pss_2048() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());

    let params: BigNumParams<18, 2048> = BigNumParams::new(
        false,
        [
            0x45648f4ade2ac1f40c18b44a2951ad,
            0xd558cced315cbced65532e416ab0ea,
            0x67c3818b41ed79f0e9e06b10b31a39,
            0x9bb9db99001fe165b2a18bfb8ff423,
            0xc792c2037f2abe206bdc987898a73b,
            0x6630acf8743e8ffca5199b195d2e32,
            0xbffc9f0464184da3de5f0efa5a705b,
            0xe14bd49bd3ec93d8f3e84f47a32e6d,
            0x2d6abfec39882cd67f7804b9ff278e,
            0x1140883fa39129d297ebee534cdf58,
            0x96bc387e08849589aa1dda5d381cd2,
            0x31c60ecdf4d3c1119814b724779a9e,
            0x1a4882267e3e2e6074b40448d62087,
            0x9e015854d57eae42e5b515d357a755,
            0xb593f8dfc8434f32d7d30277b1abc,
            0x4e7184b54966a30552fc92df470aa,
            0xa8a3c9172762978b03464671f8288e,
            0xba,
        ],
        [
            0x1c63831dbaa98693ab59ca2ae5a88,
            0x3e67cf06ca2556701f3aa8d158552,
            0x7c63171078a831165ed8b2dd116675,
            0x9e1f1bca55d0e220e58ddbbb387972,
            0xd7c72f20722cc7af897d5819424801,
            0xf0434a631cffe4c4d56874bff93661,
            0x8767e83f45cfff15cca95d5dc6f48c,
            0xf210d697748e9ad45c0f7c3ed3bda8,
            0xc960d59cb9dd48d50e12c2ef04dda2,
            0xbf07cf1ecc532686848dca09d061c2,
            0xc491a60be200f9574ad6aa31977a4f,
            0x67681170f25ab2aff941b18e21e1bd,
            0xc485fc6deda1ba84f2bfcfbea2c044,
            0x776bc3eac3728ec7f85ca2496ee8e4,
            0x4d82eeb8ecdc1ec53280fce96c05e,
            0x514088d39ff1cae50d2f67db91458f,
            0x9c1553de9eef61a83b288c4d11610e,
            0x15f1,
        ],
    );

    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum {
        params,
        limbs: [
            0xcce57aaed9eed21edef9d96d9ebdf8,
            0x181f152657736ea458462ff45b1d81,
            0x9df8c00fefe67c3a727c1f84641d2a,
            0xe3bb299609d4f4bfe7e979123f6962,
            0x6cf987c686983f184262419dc8d64b,
            0xedc086f713d60c9d661a4e7fdae380,
            0xb95ada34d5b9217d9eaa89d1d7a3d1,
            0xec275d1d4e3e74296eab26318df81f,
            0x3c943e2d3e12f1394952de70d92ac9,
            0x4a4e8a625138a533b9b71cbb03c991,
            0xa5379dfc363e79c5a55ad71a01948e,
            0x9340e047e0d4be67ac7f1517fe2673,
            0xdf2606ac8cbbcad391c5e925bf5082,
            0x249690032f10b7986e7edbb8ec0d6a,
            0x8c07da4fbed69ab71f127fb5edf73c,
            0x64aefd403b6a4353ebdc9b7fce82bc,
            0x5ecc107633bc4cc1a3adb545b474de,
            0x7b,
        ],
    };

    assert(verify_sha256_pss(sha256_hash, signature, 2048));
}

#[test]
fn test_verify_sha256_pss_4096() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
    let params: BigNumParams<35, 4096> = BigNumParams::new(
        false,
        [
            0xa6222b52f49e7258fe4fee04ea2d9,
            0x2fd64c9fce4dba1e003e9b0947ee34,
            0xf46a24f43be90f258013ba55794c6a,
            0xda8100ed967a7577f4144295e37b68,
            0x8545db58ed5cb1a78661a725c2e2df,
            0xfc1673fba9882dc0c1bf1ebd95e9a7,
            0xf8863f5481969b504d93ec7b3634f,
            0xafedf06a9d7583f1c06b2ee8a1f2b8,
            0x375c3f57b70cb7fc6b934445a97ebe,
            0xd89ad291b95a70bf4922b45d2efff8,
            0x2bf000f6408944083d93e45030e827,
            0xf55cb42313719c7a2bfa07b3eb1ed4,
            0x6d8656a0f3b41fa1a717140dc5ce90,
            0x404b10d983681bd3f9ed1534d5bfa2,
            0xced48aead2b9ba16f08a0fb968a96c,
            0x43acf088910c3322f7da5c2d0a2211,
            0x58b7e2d7b7f268eb990fc464defe90,
            0x2be3be3a4fedf432a98dda3c220958,
            0xf9156a2bafb69ef294360c25d22759,
            0x1b7e6763845875a1886345b4ee8940,
            0xa40ae130e9762120841e1930873975,
            0x2d883272a543cf8fd0cdfbecc94367,
            0x715a88142fec78eb472f6684cd942d,
            0xdd302fea25298915e2db875f6ab621,
            0x6612ced822df9c00c368466391fe23,
            0x48acb5eea186585b9c24443397b8fb,
            0x53fc8b5e2bedc30b81f632371f1e8a,
            0x7ef026faeb670fc44abfeee192bec6,
            0xb07bb4bfb19773a319052ffac029a9,
            0x81c21e9e538893cb04debde34bc02e,
            0x823427edc35eaf0a2f5d493318db74,
            0xbad02f47a1ff078d0103affc3792b1,
            0xe297eab3b3edafcf99c2ba52cb8424,
            0x3e7e575d40629a07980fa71996e807,
            0xc27a,
        ],
        [
            0x54aba16603d87dec091aa1821ce3b0,
            0x8f6a9c560fe4f4d5fb83999853bd1c,
            0x4d9b41fcc316ae6b1a9bb7eefa7713,
            0x623fcac3bfa0aa5f932acc0f0f28c9,
            0xb29eca15e9ba6d9bbcd2ac543f9558,
            0x43689b8fe8bbb48269c2fb3b03a624,
            0xc6f8b1cbefb4cb7d2eec1bc951808b,
            0x4074a7837f67403f497133fee0e29,
            0x536ba97fd34f92aae1e0354bc17db0,
            0x784c203e438e43ddddae491fd0c0e9,
            0xf41ae3f5f5060d212bcc7c4ee71d2,
            0xe539fd3b39a98377199ae15d165ea,
            0xd13be03a50e9694c4c84e2541303ed,
            0x38136b8771f62c9778e1f812ceadec,
            0x23bea00ab5c2efafde2c8ea46673a8,
            0xa4d3523ba9389da81c46adde61fece,
            0xadb3053369bb6e7233eea01174caa2,
            0x68995fa9f373e420a9f6e6fa2329e7,
            0x38f83f074d3ee3674e7336349a0d4e,
            0xd9ecb79c431b08a695e4808a636a48,
            0x3498c268b8bb4936c9e8f9fa73da27,
            0x123ed10b1358dde62125f1191fc922,
            0xa5a412e4c3c73dbb5cba119c48af2d,
            0xbee3217219d507e4a6ff74b9b9eee5,
            0x2ee5efcaee7ca45ffcd85f10eeb21b,
            0xb977bc65277e5723737f52905837bc,
            0xd1fd3aa6e7717bceccf73b04c8bf2d,
            0x7964355f3acd61d2408ce20a964740,
            0xfc2e76f487e6ca0e6bcadbf9d3801d,
            0xfb0ea20336cf95062efb880d82cab5,
            0x6884d9ca882e37df90f8f5c603b7b1,
            0x9be945fc633fcc0dd2b84ec1debef5,
            0x8d834cbc2c9a3aa4a85a3994bc569d,
            0x7055060035c122b095b75e6de37d48,
            0x150fc2,
        ],
    );
    let signature: RuntimeBigNum<35, 4096> = RuntimeBigNum {
        params,
        limbs: [
            0xdeb402a595b32a248fd427ed84c743,
            0x75f1b3656f2eb61c3e4164375052cf,
            0x33aa80998875b8b48263611706607b,
            0xd9c80be79f586e80ac3af1a8d5ea53,
            0xf0b116fd85546f206ae49d041d0223,
            0x406a397f56e62863aa7b6ed1429dec,
            0xd7e0bbd7ac00a419f3fef0098e904f,
            0x303665df221e3691c84c6502d1b807,
            0xb2ce0e36df94a88f8120b53a0bcb84,
            0xe8e55991ffdb5b731b77cb249991d1,
            0xbaa946c3acb9696a4d416d86291fd2,
            0x7746a7486603b1cfb5dc5f800ee409,
            0x567d9470319309142967b699404091,
            0x5ee6fbb50c8637805ec6c7780a9e0a,
            0x32bf8a51bc178cdb664ca911c857ea,
            0xe928146ddcc0865c10215611955243,
            0x5d12083acd2e3a1b7f7313dea0b894,
            0x8620f5ba7615db0a3285c735813a73,
            0x7b84f0e392902e84792c4879f48fbc,
            0x1437df81c544ea4d7fdb020bfb7fcb,
            0x09fb8b36d3a58a6a5fff27c1664d97,
            0xef70898862d34d8f2d7c1bb1fb8103,
            0xd24f625196ae71e3064596a7dd80f3,
            0xeb646b3e5958fc213a0f711a5c68c4,
            0x7f57a200d1894a07a33610c56a543d,
            0xa54baf3fadfe09f896d2f2c88df7e7,
            0xb605122c80e189236329bbf9ad6c9f,
            0xa6ac0b396215d0f50b3705cd08788a,
            0xdad6946e3c27a25ab484a0ed338788,
            0x874dfd4c3723c395217a881b93283a,
            0xf5ac1d98a50f59a40db4e2d4864a07,
            0x9d6ed5b0d10028a291588a3359cd32,
            0x7d8b67a1bad38a5ec750dc27bc8ae0,
            0xa2ddd25f61adf97f5e2e8a0ef99ba8,
            0x2244,
        ],
    };
    assert(verify_sha256_pss(sha256_hash, signature, 4096));
}

// doesnt work yet need better method
// #[test]
fn test_verify_sha256_pss_1964() {
    let sha256_hash: [u8; 32] = dep::std::hash::sha256("Hello World! This is Noir-RSA".as_bytes());
    let params: BigNumParams<17, 1964> = BigNumParams::new(
        false,
        [
            0xe62ce4613d178a8af9154a28c804c9,
            0xe9c80bb90ee949aa26d5554f5b7323,
            0xa823c32e66dce57c7617704f092c82,
            0x8b7eee92772e414a23ee9dd5ef843a,
            0x6590039cb62daeea7a96faf674175c,
            0x2905f4400973a1442181701f12f30d,
            0xc5f0a37929848a5fbe070ddc915dee,
            0x2ada1490d935ef7700c43dc2565539,
            0xa99acb3b526abb963d71e527c17e2e,
            0xf9d79341476659c231dc93313fb440,
            0x168d8abd0528fa146b6401034358f2,
            0x6d7386e7d66bec5392a463d34f7b5d,
            0xeb245f85612f76849ce32cd5f9011e,
            0x2d171c40f36f34eeb17b4643c7f9e2,
            0xd582273cf4c5fb0c195ccac1526478,
            0x1df64d0a6c95698d34c1b16640ad92,
            0xdd8e29ecdc0,
        ],
        [
            0x7893f159b37d9b4d46e77e420d3315,
            0x97913c7ea0db74a13b793686c0fa,
            0x3eddab2786c599e1fcd99b06a1b151,
            0x6f922b72a2386f483d35d5017ef102,
            0xcf9ede21d4ca70a045ccdac95c1e9,
            0xbe7c0cc79955f74eafb82000838e19,
            0x26bd0fc82288bde663f5dff239b55b,
            0x95f857821550531b848b454b4f7dc7,
            0xef08d9d594fbf1547ac00a03323aa7,
            0x3bb9f9263bfe85814477c58de4934d,
            0x214887fd218e3573f1aae50917a816,
            0xe6f1abc97678adf59b2008645d8802,
            0x28dd35618649eef12941db95081242,
            0xc13764316f70444e7120b6ae5088f5,
            0xefb1aba9512f1b2c88db34a4938796,
            0x6aed9a143fb37749eca936a60ae25c,
            0x127ccb9568ee6,
        ],
    );

    let signature: RuntimeBigNum<17, 1964> = RuntimeBigNum {
        params,
        limbs: [
            0x37c3a3f915fb9e787412d457ec4a63,
            0xd60918c40b6c50bcc8afa8d1ea754f,
            0x98eec8d63deeb22eca4f9d15b7e935,
            0xc841db8c9930934dcc8171a5fee4b4,
            0x3341bdb96ed1d734959e257dbc85ca,
            0x32701c7557ca04c15cd9e18f45d37b,
            0xefd3dae979f5a920654dc7a3ea2277,
            0x1d6724ec09b112e8776c115874a53f,
            0xf403d3593f85b9ab421fa26bf99298,
            0x04e85e3628f4c3fc254a92c56ba0b8,
            0x975bb82f1fe3c3d1656e098682f69f,
            0x0ad72d532c8e6e17398d918c360973,
            0xc4ba256370766c633e77d4102a8919,
            0xc4d3bb32bc889aca394bef272d3f71,
            0x5d56778a3d1ad3117471d4060761b0,
            0x5fd5d71fec72f615614d6347935f35,
            0x09ab8ab67e43,
        ],
    };
    assert(verify_sha256_pss(sha256_hash, signature, 4096));

}

#[test]
fn test_verify_sha256_pss_jwt() {
    let hash: [u8; 32] = [
        190, 196, 184, 50, 102, 89, 57, 43, 211, 245, 140, 168, 170, 163, 80, 128, 25, 139, 25, 68,
        239, 215, 154, 164, 148, 234, 47, 212, 6, 140, 157, 110,
    ];
    let params: BigNumParams<18, 2048> = BigNumParams::new(
        false,
        [
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
        ],
        [
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
        ],
    );
    let signature: RuntimeBigNum<18, 2048> = RuntimeBigNum {
        params,
        limbs: [
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
        ],
    };

    assert(verify_sha256_pss(hash, signature, 2048));
}
