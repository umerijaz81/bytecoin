use std::collections::BTreeMap;

use bytecoin_onyx_sdk::{
    multisig_application, nft_application, swap_application, vesting_application, JsonObject,
    JsonValue, SdkError, WalletRpcCodec, PROFILE_NAME, STANDARD_SCHEMA_HASHES,
};

fn object(fields: &[&str]) -> JsonObject {
    fields
        .iter()
        .map(|field| ((*field).to_owned(), JsonValue::Null))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn frozen_rpc_profile_is_exact_and_fail_closed() {
    let cases: &[(&str, &[&str], &[&str])] = &[
        (
            "get_onyx_status",
            &["address_index"],
            &["address", "balance", "note_count", "commitment_root"],
        ),
        (
            "get_onyx_asset_balance",
            &["program_id", "asset_id"],
            &["balance", "unspent_note_count"],
        ),
        (
            "get_onyx_program_status",
            &["program_id"],
            &[
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
        ),
        (
            "create_onyx_transaction",
            &["address", "amount", "fee", "expiry_height", "memo"],
            &["binary_transaction", "transaction_hash"],
        ),
        (
            "create_onyx_token_transaction",
            &[
                "address",
                "program_id",
                "amount",
                "fee",
                "expiry_height",
                "memo",
            ],
            &["binary_transaction", "transaction_hash"],
        ),
        (
            "create_onyx_program_deployment",
            &[
                "max_supply",
                "metadata",
                "activation_height",
                "deactivation_height",
                "fee",
                "expiry_height",
            ],
            &["binary_transaction", "transaction_hash", "program_id"],
        ),
        (
            "create_onyx_standard_program_deployment",
            &[
                "kind",
                "activation_height",
                "deactivation_height",
                "fee",
                "expiry_height",
            ],
            &["binary_transaction", "transaction_hash", "program_id"],
        ),
        (
            "create_onyx_standard_program_call",
            &[
                "program_id",
                "valid_from_height",
                "expiry_height",
                "application",
                "prior_state",
                "next_state",
                "witness",
            ],
            &["binary_transaction", "transaction_hash"],
        ),
        (
            "create_onyx_token_issuance",
            &["address", "program_id", "amount", "expiry_height", "memo"],
            &["binary_transaction", "transaction_hash", "sequence"],
        ),
        (
            "create_onyx_bridge",
            &[
                "address",
                "legacy_amount",
                "fee",
                "legacy_stack_index",
                "legacy_key_image",
                "expiry_height",
                "memo",
            ],
            &["unsigned_bridge", "ownership_sighash"],
        ),
        (
            "finalize_onyx_bridge",
            &["unsigned_bridge", "ownership_signature"],
            &["binary_transaction", "transaction_hash"],
        ),
    ];
    assert_eq!(WalletRpcCodec::methods().len(), cases.len());
    for (method, request_fields, response_fields) in cases {
        let id = JsonValue::from(*method);
        let request = WalletRpcCodec::request(method, object(request_fields), id.clone()).unwrap();
        let JsonValue::Object(request) = request else {
            panic!("request was not an object");
        };
        assert_eq!(request.get("jsonrpc"), Some(&JsonValue::from("2.0")));
        assert_eq!(request.get("method"), Some(&JsonValue::from(*method)));
        let response = JsonValue::Object(JsonObject::from([
            ("jsonrpc".to_owned(), JsonValue::from("2.0")),
            ("id".to_owned(), id.clone()),
            (
                "result".to_owned(),
                JsonValue::Object(object(response_fields)),
            ),
        ]));
        assert_eq!(
            WalletRpcCodec::validate_response(method, response, Some(&id)).unwrap(),
            object(response_fields)
        );
    }

    assert!(matches!(
        WalletRpcCodec::request("unknown", JsonObject::new(), JsonValue::from(1_u64)),
        Err(SdkError::UnknownMethod(_))
    ));
    let mut extra = object(&["address_index"]);
    extra.insert("extra".to_owned(), JsonValue::Bool(true));
    assert!(matches!(
        WalletRpcCodec::request("get_onyx_status", extra, JsonValue::from(1_u64)),
        Err(SdkError::InvalidFields { .. })
    ));
}

#[test]
fn canonical_json_and_rpc_errors_are_strict() {
    let value = JsonValue::Object(BTreeMap::from([
        (
            "z".to_owned(),
            JsonValue::Object(BTreeMap::from([
                ("b".to_owned(), JsonValue::from(2_u64)),
                ("a".to_owned(), JsonValue::from(1_u64)),
            ])),
        ),
        ("a".to_owned(), JsonValue::Bool(true)),
    ]));
    assert_eq!(
        WalletRpcCodec::canonical_json(&value).unwrap(),
        r#"{"a":true,"z":{"a":1,"b":2}}"#
    );
    let response = JsonValue::Object(JsonObject::from([
        ("jsonrpc".to_owned(), JsonValue::from("2.0")),
        ("id".to_owned(), JsonValue::from(1_u64)),
        (
            "error".to_owned(),
            JsonValue::Object(JsonObject::from([
                ("code".to_owned(), JsonValue::from(-1_i64)),
                ("message".to_owned(), JsonValue::from("no")),
            ])),
        ),
    ]));
    assert!(matches!(
        WalletRpcCodec::validate_response(
            "get_onyx_status",
            response,
            Some(&JsonValue::from(1_u64))
        ),
        Err(SdkError::Rpc { .. })
    ));
    let malformed_error = JsonValue::Object(JsonObject::from([
        ("jsonrpc".to_owned(), JsonValue::from("2.0")),
        ("id".to_owned(), JsonValue::from(1_u64)),
        (
            "error".to_owned(),
            JsonValue::Object(JsonObject::from([
                ("code".to_owned(), JsonValue::Number("01".to_owned())),
                ("message".to_owned(), JsonValue::from("no")),
            ])),
        ),
    ]));
    assert!(matches!(
        WalletRpcCodec::validate_response(
            "get_onyx_status",
            malformed_error,
            Some(&JsonValue::from(1_u64))
        ),
        Err(SdkError::InvalidResponse(_))
    ));
    assert!(WalletRpcCodec::canonical_json(&JsonValue::Number("01".into())).is_err());
}

#[test]
fn standard_application_bytes_match_the_frozen_profile() {
    let repeated = |value| [value; 32];
    let mut field = [0_u8; 32];
    field[0] = 5;
    assert_eq!(
        hex(&nft_application(&repeated(1), &repeated(2), 128, 1).unwrap()),
        format!("0101{}{}800101", "01".repeat(32), "02".repeat(32))
    );
    assert_eq!(
        hex(&vesting_application(&repeated(3), &repeated(4), 300).unwrap()),
        format!("0102{}{}ac02", "03".repeat(32), "04".repeat(32))
    );
    assert_eq!(
        hex(&multisig_application(&field, &repeated(6), 2, 3).unwrap()),
        format!("0103{}{}0203", hex(&field), "06".repeat(32))
    );
    assert_eq!(
        hex(&swap_application(&repeated(7), &field, 9, true).unwrap()),
        format!("0104{}{}0901", "07".repeat(32), hex(&field))
    );
    assert_eq!(STANDARD_SCHEMA_HASHES.len(), 4);
    assert!(nft_application(&[0; 32], &repeated(2), 0, 1).is_err());
    assert!(nft_application(&repeated(1), &repeated(2), 0, 0).is_err());
    assert!(multisig_application(&field, &repeated(1), 3, 2).is_err());
    assert!(multisig_application(
        &[
            1, 0, 0, 0, 237, 48, 45, 153, 27, 249, 76, 9, 252, 152, 70, 34, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 64,
        ],
        &repeated(1),
        1,
        1,
    )
    .is_err());
}

#[test]
fn packaged_profile_identity_is_frozen() {
    let profile = include_str!("../wallet-rpc-v1.json");
    assert!(profile.contains(&format!(r#""profile": "{PROFILE_NAME}""#)));
    for method in WalletRpcCodec::methods() {
        assert!(profile.contains(&format!(r#""{method}""#)));
    }
}
