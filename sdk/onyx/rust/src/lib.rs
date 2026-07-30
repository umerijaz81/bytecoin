//! Dependency-free, transport-agnostic binding for the Onyx SDK v1 profile.

use std::collections::BTreeMap;
use std::fmt;

pub const PROFILE_NAME: &str = "bytecoin-onyx-wallet-rpc-v1";
pub const STANDARD_APPLICATION_VERSION: u8 = 1;
pub const STANDARD_SCHEMA_HASHES: [(&str, &str); 4] = [
    (
        "nft",
        "204730978f788b8d1e458ee81c1c12ff39d0444f174fe9d192246d80890bb132",
    ),
    (
        "vesting",
        "c36efa02930c2551179a949214f1a181720ddd8364e44a197c7a0b756cd0862c",
    ),
    (
        "multisig",
        "8703b1c751de7881667f76507fdf7f04a30399da2c4b1bb27f8b91e86a5ba589",
    ),
    (
        "swap",
        "8738062476880a23afdd40b5c64c8ec2120d8c6981315dba90776266ddde4fce",
    ),
];

const PASTA_FP_MODULUS_LE: [u8; 32] = [
    1, 0, 0, 0, 237, 48, 45, 153, 27, 249, 76, 9, 252, 152, 70, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 64,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    /// A caller-decoded canonical JSON number token.
    Number(String),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl From<bool> for JsonValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<u64> for JsonValue {
    fn from(value: u64) -> Self {
        Self::Number(value.to_string())
    }
}

impl From<i64> for JsonValue {
    fn from(value: i64) -> Self {
        Self::Number(value.to_string())
    }
}

impl From<&str> for JsonValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<String> for JsonValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

pub type JsonObject = BTreeMap<String, JsonValue>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SdkError {
    UnknownMethod(String),
    InvalidFields {
        label: String,
        missing: Vec<String>,
        unknown: Vec<String>,
    },
    InvalidResponse(&'static str),
    ResponseIdMismatch,
    Rpc {
        code: String,
        message: String,
        data: Option<JsonValue>,
    },
    InvalidArgument(&'static str),
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SdkError {}

struct Method {
    name: &'static str,
    request: &'static [&'static str],
    response: &'static [&'static str],
}

const METHODS: &[Method] = &[
    Method {
        name: "get_onyx_status",
        request: &["address_index"],
        response: &["address", "balance", "note_count", "commitment_root"],
    },
    Method {
        name: "get_onyx_asset_balance",
        request: &["program_id", "asset_id"],
        response: &["balance", "unspent_note_count"],
    },
    Method {
        name: "get_onyx_program_status",
        request: &["program_id"],
        response: &[
            "issuer",
            "max_supply",
            "issued_supply",
            "remaining_supply",
            "next_sequence",
            "query_height",
            "activation_height",
            "deactivation_height",
            "active",
            "metadata",
        ],
    },
    Method {
        name: "create_onyx_transaction",
        request: &["address", "amount", "fee", "expiry_height", "memo"],
        response: &["binary_transaction", "transaction_hash"],
    },
    Method {
        name: "create_onyx_token_transaction",
        request: &[
            "address",
            "program_id",
            "amount",
            "fee",
            "expiry_height",
            "memo",
        ],
        response: &["binary_transaction", "transaction_hash"],
    },
    Method {
        name: "create_onyx_program_deployment",
        request: &[
            "max_supply",
            "metadata",
            "activation_height",
            "deactivation_height",
            "fee",
            "expiry_height",
        ],
        response: &["binary_transaction", "transaction_hash", "program_id"],
    },
    Method {
        name: "create_onyx_standard_program_deployment",
        request: &[
            "kind",
            "activation_height",
            "deactivation_height",
            "fee",
            "expiry_height",
        ],
        response: &["binary_transaction", "transaction_hash", "program_id"],
    },
    Method {
        name: "create_onyx_standard_program_call",
        request: &[
            "program_id",
            "valid_from_height",
            "expiry_height",
            "application",
            "prior_state",
            "next_state",
            "witness",
        ],
        response: &["binary_transaction", "transaction_hash"],
    },
    Method {
        name: "create_onyx_token_issuance",
        request: &["address", "program_id", "amount", "expiry_height", "memo"],
        response: &["binary_transaction", "transaction_hash", "sequence"],
    },
    Method {
        name: "create_onyx_bridge",
        request: &[
            "address",
            "legacy_amount",
            "fee",
            "legacy_stack_index",
            "legacy_key_image",
            "expiry_height",
            "memo",
        ],
        response: &["unsigned_bridge", "ownership_sighash"],
    },
    Method {
        name: "finalize_onyx_bridge",
        request: &["unsigned_bridge", "ownership_signature"],
        response: &["binary_transaction", "transaction_hash"],
    },
];

fn method(name: &str) -> Result<&'static Method, SdkError> {
    METHODS
        .iter()
        .find(|entry| entry.name == name)
        .ok_or_else(|| SdkError::UnknownMethod(name.to_owned()))
}

fn exact_fields(object: &JsonObject, expected: &[&str], label: &str) -> Result<(), SdkError> {
    let mut missing: Vec<String> = expected
        .iter()
        .filter(|name| !object.contains_key(**name))
        .map(|name| (*name).to_owned())
        .collect();
    let mut unknown: Vec<String> = object
        .keys()
        .filter(|name| !expected.contains(&name.as_str()))
        .cloned()
        .collect();
    missing.sort();
    unknown.sort();
    if missing.is_empty() && unknown.is_empty() {
        Ok(())
    } else {
        Err(SdkError::InvalidFields {
            label: label.to_owned(),
            missing,
            unknown,
        })
    }
}

pub struct WalletRpcCodec;

impl WalletRpcCodec {
    pub fn methods() -> Vec<&'static str> {
        let mut names: Vec<_> = METHODS.iter().map(|entry| entry.name).collect();
        names.sort();
        names
    }

    pub fn request(
        method_name: &str,
        params: JsonObject,
        request_id: JsonValue,
    ) -> Result<JsonValue, SdkError> {
        let contract = method(method_name)?;
        exact_fields(
            &params,
            contract.request,
            &format!("invalid {method_name} request"),
        )?;
        Ok(JsonValue::Object(JsonObject::from([
            ("id".to_owned(), request_id),
            ("jsonrpc".to_owned(), JsonValue::from("2.0")),
            ("method".to_owned(), JsonValue::from(method_name)),
            ("params".to_owned(), JsonValue::Object(params)),
        ])))
    }

    pub fn validate_response(
        method_name: &str,
        response: JsonValue,
        request_id: Option<&JsonValue>,
    ) -> Result<JsonObject, SdkError> {
        let contract = method(method_name)?;
        let JsonValue::Object(mut response) = response else {
            return Err(SdkError::InvalidResponse(
                "wallet RPC response must be an object",
            ));
        };
        if response.get("jsonrpc") != Some(&JsonValue::from("2.0")) || !response.contains_key("id")
        {
            return Err(SdkError::InvalidResponse(
                "wallet RPC response must be JSON-RPC 2.0 with an id",
            ));
        }
        if request_id.is_some_and(|expected| response.get("id") != Some(expected)) {
            return Err(SdkError::ResponseIdMismatch);
        }
        if response.contains_key("error") {
            exact_fields(
                &response,
                &["jsonrpc", "id", "error"],
                "wallet RPC error response",
            )?;
            let Some(JsonValue::Object(mut error)) = response.remove("error") else {
                return Err(SdkError::InvalidResponse(
                    "wallet RPC error object is malformed",
                ));
            };
            let allowed = if error.contains_key("data") {
                &["code", "message", "data"][..]
            } else {
                &["code", "message"][..]
            };
            exact_fields(&error, allowed, "wallet RPC error object")?;
            let code = match error.remove("code") {
                Some(JsonValue::Number(value)) if canonical_number(&value) => value,
                _ => {
                    return Err(SdkError::InvalidResponse(
                        "wallet RPC error code is malformed",
                    ))
                }
            };
            let message = match error.remove("message") {
                Some(JsonValue::String(value)) => value,
                _ => {
                    return Err(SdkError::InvalidResponse(
                        "wallet RPC error message is malformed",
                    ))
                }
            };
            return Err(SdkError::Rpc {
                code,
                message,
                data: error.remove("data"),
            });
        }
        exact_fields(
            &response,
            &["jsonrpc", "id", "result"],
            "wallet RPC result response",
        )?;
        let Some(JsonValue::Object(result)) = response.remove("result") else {
            return Err(SdkError::InvalidResponse(
                "wallet RPC result must be an object",
            ));
        };
        exact_fields(
            &result,
            contract.response,
            &format!("invalid {method_name} result"),
        )?;
        Ok(result)
    }

    pub fn canonical_json(value: &JsonValue) -> Result<String, SdkError> {
        let JsonValue::Object(_) = value else {
            return Err(SdkError::InvalidArgument(
                "canonical JSON root must be an object",
            ));
        };
        let mut output = String::new();
        write_json(value, &mut output)?;
        Ok(output)
    }
}

fn write_json(value: &JsonValue, output: &mut String) -> Result<(), SdkError> {
    match value {
        JsonValue::Null => output.push_str("null"),
        JsonValue::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        JsonValue::Number(value) => {
            if !canonical_number(value) {
                return Err(SdkError::InvalidArgument("JSON number is not canonical"));
            }
            output.push_str(value);
        }
        JsonValue::String(value) => write_string(value, output),
        JsonValue::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_json(value, output)?;
            }
            output.push(']');
        }
        JsonValue::Object(values) => {
            output.push('{');
            for (index, (key, value)) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_string(key, output);
                output.push(':');
                write_json(value, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn canonical_number(value: &str) -> bool {
    if value == "0" {
        return true;
    }
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    !unsigned.is_empty()
        && !unsigned.starts_with('0')
        && unsigned.bytes().all(|byte| byte.is_ascii_digit())
}

fn write_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value <= '\u{1f}' => {
                use std::fmt::Write;
                write!(output, "\\u{:04x}", value as u32).expect("writing to String cannot fail");
            }
            value => output.push(value),
        }
    }
    output.push('"');
}

fn checked_bytes32(value: &[u8], field: bool) -> Result<[u8; 32], SdkError> {
    let result: [u8; 32] = value
        .try_into()
        .map_err(|_| SdkError::InvalidArgument("identifier must be exactly 32 bytes"))?;
    if result.iter().all(|byte| *byte == 0) {
        return Err(SdkError::InvalidArgument("identifier must be nonzero"));
    }
    if field && !little_endian_less(&result, &PASTA_FP_MODULUS_LE) {
        return Err(SdkError::InvalidArgument(
            "field must be a canonical Pasta field encoding",
        ));
    }
    Ok(result)
}

fn little_endian_less(left: &[u8; 32], right: &[u8; 32]) -> bool {
    for index in (0..32).rev() {
        if left[index] != right[index] {
            return left[index] < right[index];
        }
    }
    false
}

fn append_varint(mut value: u64, output: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return;
        }
    }
}

pub fn nft_application(
    collection_id: &[u8],
    token_id: &[u8],
    serial: u64,
    transfer_nonce: u64,
) -> Result<Vec<u8>, SdkError> {
    if transfer_nonce == 0 {
        return Err(SdkError::InvalidArgument("transfer nonce must be positive"));
    }
    let mut output = vec![STANDARD_APPLICATION_VERSION, 1];
    output.extend_from_slice(&checked_bytes32(collection_id, false)?);
    output.extend_from_slice(&checked_bytes32(token_id, false)?);
    append_varint(serial, &mut output);
    append_varint(transfer_nonce, &mut output);
    Ok(output)
}

pub fn vesting_application(
    schedule_id: &[u8],
    beneficiary: &[u8],
    unlock_height: u64,
) -> Result<Vec<u8>, SdkError> {
    let mut output = vec![STANDARD_APPLICATION_VERSION, 2];
    output.extend_from_slice(&checked_bytes32(schedule_id, false)?);
    output.extend_from_slice(&checked_bytes32(beneficiary, false)?);
    append_varint(unlock_height, &mut output);
    Ok(output)
}

pub fn multisig_application(
    policy_commitment: &[u8],
    action_digest: &[u8],
    threshold: u64,
    participant_count: u64,
) -> Result<Vec<u8>, SdkError> {
    if threshold == 0
        || participant_count == 0
        || participant_count > 16
        || threshold > participant_count
    {
        return Err(SdkError::InvalidArgument(
            "threshold must not exceed a participant count in [1, 16]",
        ));
    }
    let mut output = vec![STANDARD_APPLICATION_VERSION, 3];
    output.extend_from_slice(&checked_bytes32(policy_commitment, true)?);
    output.extend_from_slice(&checked_bytes32(action_digest, false)?);
    append_varint(threshold, &mut output);
    append_varint(participant_count, &mut output);
    Ok(output)
}

pub fn swap_application(
    swap_id: &[u8],
    hashlock: &[u8],
    timeout_height: u64,
    refund: bool,
) -> Result<Vec<u8>, SdkError> {
    let mut output = vec![STANDARD_APPLICATION_VERSION, 4];
    output.extend_from_slice(&checked_bytes32(swap_id, false)?);
    output.extend_from_slice(&checked_bytes32(hashlock, true)?);
    append_varint(timeout_height, &mut output);
    output.push(u8::from(refund));
    Ok(output)
}
