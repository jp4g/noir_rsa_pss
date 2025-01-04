use num_bigint::BigUint;
use rsa::pkcs1v15::Signature;
use rsa::{RsaPrivateKey, RsaPublicKey};
use signature::Keypair;
use signature::RandomizedSignerMut;
use std::env;
use toml::Value;

use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use sha2::{Digest, Sha256};

use clap::{App, Arg};

use noir_bignum_paramgen::{
    bn_limbs, compute_barrett_reduction_parameter, split_into_120_bit_limbs,
};

fn format_limbs_as_hex(limbs: &Vec<BigUint>) -> String {
    limbs
        .iter()
        .map(|a| format!("0x{:x}", a))
        .collect::<Vec<_>>()
        .join(", ")
}

fn format_limbs_as_toml_value(limbs: &Vec<BigUint>) -> Vec<Value> {
    limbs
        .iter()
        .map(|a| Value::String(format!("0x{:x}", a)))
        .collect()
}

fn generate_2048_bit_signature_parameters(msg: &str, as_toml: bool, exponent: u32, pss: bool) {
    let mut hasher = Sha256::new();
    hasher.update(msg.as_bytes());
    let hashed_message = hasher.finalize();

    let hashed_as_bytes = hashed_message
        .iter()
        .map(|&b| b.to_string())
        .collect::<Vec<String>>()
        .join(", ");

    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
    let bits: usize = 2048;
    let priv_key: RsaPrivateKey =
        RsaPrivateKey::new_with_exp(&mut rng, bits, &BigUint::from(exponent))
            .expect("failed to generate a key");
    let pub_key: RsaPublicKey = priv_key.clone().into();

    let sig_bytes = if pss {
        let mut signing_key = rsa::pss::BlindedSigningKey::<Sha256>::new(priv_key);
        let sig = signing_key.sign_with_rng(&mut rng, msg.as_bytes());
        sig.to_vec()
    } else {
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(priv_key);
        signing_key.sign(msg.as_bytes()).to_vec()
    };

    let sig_uint: BigUint = BigUint::from_bytes_be(&sig_bytes);

    let sig_str = bn_limbs(sig_uint.clone(), 2048);

    let modulus_limbs: Vec<BigUint> = split_into_120_bit_limbs(&pub_key.n().clone(), 2048);
    let redc_param = split_into_120_bit_limbs(
        &compute_barrett_reduction_parameter(&pub_key.n().clone()),
        2048,
    );

    if as_toml {
        let sig_limbs = split_into_120_bit_limbs(&sig_uint.clone(), 2048);
        let signature_toml = Value::Array(format_limbs_as_toml_value(&sig_limbs));

        let bn = Value::Array(vec![
            Value::Array(format_limbs_as_toml_value(&modulus_limbs)),
            Value::Array(format_limbs_as_toml_value(&redc_param)),
        ]);
        let bn_toml = toml::to_string_pretty(&bn).unwrap();
        println!("bn = {}", bn_toml);
        println!("hash = [{}]", hashed_as_bytes);
        println!("[signature]");
        println!("limbs = {}", signature_toml);
    } else {
        println!("let hash: [u8; 32] = [{}];", hashed_as_bytes);
        println!(
            "let signature: BN2048 = BigNum::from_array({});",
            sig_str.as_str()
        );
        println!(
            "let bn = [\n    [{}],\n    [{}]\n];",
            format_limbs_as_hex(&modulus_limbs),
            format_limbs_as_hex(&redc_param)
        );
    }
}

fn main() {
    let matches = App::new("RSA Signature Generator")
        .arg(
            Arg::with_name("msg")
                .short("m")
                .long("msg")
                .takes_value(true)
                .help("Message to sign")
                .required(true),
        )
        .arg(
            Arg::with_name("toml")
                .short("t")
                .long("toml")
                .help("Print output in TOML format"),
        )
        .arg(
            Arg::with_name("pss")
                .short("p")
                .long("pss")
                .help("Use RSA PSS"),
        )
        .arg(
            Arg::with_name("exponent")
                .short("e")
                .long("exponent")
                .takes_value(true)
                .help("Exponent to use for the key")
                .default_value("65537"),
        )
        .get_matches();

    let msg = matches.value_of("msg").unwrap();
    let as_toml = matches.is_present("toml");
    let pss = matches.is_present("pss");
    let e: u32 = matches.value_of("exponent").unwrap().parse().unwrap();

    generate_2048_bit_signature_parameters(msg, as_toml, e, pss);
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::{Padding, Rsa};
    use openssl::sign::{RsaPssSaltlen, Signer as OpenSSLSigner, Verifier as OpenSSLVerifier};
    use pkcs1::DecodeRsaPublicKey;
    use rand::thread_rng;
    use rsa::pkcs1v15::Signature;
    use rsa::signature::{Signer, Verifier};
    use rsa::{pkcs1v15::VerifyingKey, RsaPrivateKey, RsaPublicKey};
    use serde::{Deserialize, Serialize};
    use sha2::Sha256;
    use spki::DecodePublicKey;
    use x509_parser::pem::{parse_x509_pem, Pem};
    use x509_parser::prelude::*;
    use x509_parser::x509::X509Version;

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        response_type: String,
        client_id: String,
        redirect_uri: String,
        scope: String,
        state: String,
        claims: ClaimsNested,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct ClaimsNested {
        id_token: IdToken,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct IdToken {
        openbanking_intent_id: IntentId,
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct IntentId {
        value: String,
    }

    #[test]
    fn test_signature_generation() {
        let mut rng = thread_rng();
        let bits = 2048;
        let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let pub_key: RsaPublicKey = priv_key.clone().into();
        let text: &str = "hello world";
        let signing_key = rsa::pkcs1v15::SigningKey::<Sha256>::new(priv_key);
        let sig: Vec<u8> = signing_key.sign(text.as_bytes()).to_vec();
        let verifying_key = VerifyingKey::<Sha256>::new(pub_key);

        let result = verifying_key.verify(
            text.as_bytes(),
            &Signature::try_from(sig.as_slice()).unwrap(),
        );
        result.expect("failed to verify");
    }

    #[test]
    fn test_signature_generation_pss() {
        let mut rng = thread_rng();
        let bits = 2048;
        let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let pub_key: RsaPublicKey = priv_key.clone().into();
        let text: &str = "hello world";
        let mut signing_key = rsa::pss::BlindedSigningKey::<Sha256>::new(priv_key);
        let sig: Vec<u8> = signing_key.sign_with_rng(&mut rng, text.as_bytes()).to_vec();
        let verifying_key = rsa::pss::VerifyingKey::<Sha256>::new(pub_key);

        let result = verifying_key.verify(
            text.as_bytes(),
            &rsa::pss::Signature::try_from(sig.as_slice()).unwrap(),
        );
        result.expect("failed to verify");
    }

    #[test]
    fn test_jws_pss() {
        // import verifying key
        let certificate = include_bytes!("./revolut.cert");
        let (_, pem) = parse_x509_pem(certificate).unwrap();
        let x509 = pem.parse_x509().unwrap();
        let public_key = x509.public_key();
        let rsa_key = RsaPublicKey::from_public_key_der(public_key.raw).unwrap();
        let verifying_key = rsa::pss::VerifyingKey::<Sha256>::new(rsa_key);

        // import message and signature (can be replaced by running node verifyRevolutJWS from openbanking-revolut-template)
        // print the pubkey cert and replace revolut.cert
        // print the signatureBuffer.toString('hex') and replace signature var
        // print dataToVerify and replace rawPayload.txt
        let message = include_str!("./rawPayload.txt");
        let signature = "3e42c30cab535ed5a20dcac4d405004b5098451c72a80b4460b4e3e9a4bc89f131fa6078c1f7de1d740bfd8216e0ea8b67e5d78eaa7897d02902d73c50d3d0e7bbeb4e1b4b6b4d0281bcfb0e029c44f3ea90363e4e1d7ec591e09fc2bdd832428396b054f4f89336df49c01a88bb7e5b5015e706cd179467bf9794a79474884e799fb388050a7fdcaa074225bdc1b856048640e4fb7955a06675649acd89b049b603c0dc32dc5f37796453602f36cc982f86257055162457db6aec9377e7e9fdcb31e4ebce5d6e445c722f0e6a20936bda5c83481b12013078c0cc72551373586dc69db541d729b8d02521a26bb4f42068764438443e9c9164dca039b0fb1176";
        let signature_buffer = hex::decode(signature).unwrap();

        // verify
        let result = verifying_key.verify(
            message.as_bytes(),
            &rsa::pss::Signature::try_from(&signature_buffer[..]).unwrap(),
        );
        result.expect("failed to verify");

        // print params
        // change as_toml to false to get direct variables
        generate_2048_bit_signature_parameters(message, true, 65537, true);
    }
}
