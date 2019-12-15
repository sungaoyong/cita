use byteorder::{BigEndian, ByteOrder};
use cita_types::{Address, H256};
use common_types::errors::ContractError;
use ethabi::Token;
use std::u64;
use tiny_keccak::keccak256;

pub fn extract_to_u32(data: &[u8]) -> Result<u32, ContractError> {
    if let Some(ref bytes4) = data.get(0..4) {
        Ok(BigEndian::read_u32(bytes4))
    } else {
        Err(ContractError::Internal("out of gas".to_string()))
    }
}

pub fn encode_to_u32(name: &[u8]) -> u32 {
    BigEndian::read_u32(&keccak256(name)[..])
}

pub fn encode_to_vec(name: &[u8]) -> Vec<u8> {
    keccak256(name)[0..4].to_vec()
}

pub fn clean_0x(s: &str) -> &str {
    if s.starts_with("0x") {
        &s[2..]
    } else {
        s
    }
}

pub fn get_latest_key(target: u64, keys: Vec<&u64>) -> u64 {
    if target == 0 {
        return 0;
    }

    for i in 0..keys.len() {
        let index = keys.len() - i - 1;
        if *keys[index] <= target {
            return *keys[index];
        }
    }
    0
}

pub fn check_same_length(conts: &[Address], funcs: &[Vec<u8>]) -> bool {
    if conts.len() == funcs.len() && conts.len() > 0 {
        return true;
    }
    false
}

pub fn h256_to_bool(a: H256) -> bool {
    if a == H256::from(1) {
        return true;
    }
    false
}

pub fn string_to_u64(s: &str) -> u64 {
    if let Ok(u) = s.parse::<u64>() {
        return u;
    }
    0
}

pub fn string_to_bool(s: &str) -> bool {
    if let Ok(t) = s.parse::<bool>() {
        return t;
    }
    false
}

pub fn hex_to_integer(s: &str) -> u64 {
    if let Ok(r) = u64::from_str_radix(s, 16) {
        return r;
    }
    0
}

pub fn encode_string(str: &str) -> String {
    let mut tokens = Vec::new();
    tokens.push(Token::String(str.to_string()));
    let bin = ethabi::encode(&tokens);
    hex::encode(&bin)
}

pub fn string_to_static_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}
