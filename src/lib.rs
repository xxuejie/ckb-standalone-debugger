pub mod transaction;

use crate::transaction::{MockResourceLoader, MockTransaction, ReprMockTransaction, Resource};
use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_script::{ScriptGroupType, TransactionScriptsVerifier, TxVerifyEnv};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::resolve_transaction, hardfork::HardForkSwitch, Cycle, EpochNumberWithFraction,
        HeaderView,
    },
    packed::{Byte32, CellOutput, OutPoint},
    prelude::*,
    H256,
};
use faster_hex::{hex_decode_fallback, hex_encode_fallback};
use js_sys::Function as JsFunction;
use serde_derive::{Deserialize, Serialize};
use serde_json::{from_str as from_json_str, to_string as to_json_string};
use serde_plain::from_str as from_plain_str;
use std::collections::HashSet;
use wasm_bindgen::prelude::*;

pub struct DummyResourceLoader {}

impl MockResourceLoader for DummyResourceLoader {
    fn get_header(&mut self, hash: H256) -> Result<Option<HeaderView>, String> {
        return Err(format!("Header {:x} is missing!", hash));
    }

    fn get_live_cell(
        &mut self,
        out_point: OutPoint,
    ) -> Result<Option<(CellOutput, Bytes, Option<Byte32>)>, String> {
        return Err(format!("Cell: {:?} is missing!", out_point));
    }
}

pub fn run(
    mock_tx: &MockTransaction,
    script_group_type: &ScriptGroupType,
    script_hash: &Byte32,
    max_cycle: Cycle,
    debug_printer: Option<Box<dyn Fn(&Byte32, &str)>>,
    version: u32,
) -> Result<Cycle, String> {
    let resource = Resource::from_both(mock_tx, DummyResourceLoader {})?;
    let tx = mock_tx.core_transaction();
    let rtx = {
        let mut seen_inputs = HashSet::new();
        resolve_transaction(tx, &mut seen_inputs, &resource, &resource)
            .map_err(|err| format!("Resolve transaction error: {:?}", err))?
    };
    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_pr_0234(200)
        .rfc_pr_0237(200)
        .build()
        .unwrap();
    let consensus = ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build();
    let epoch = match version {
        0 => EpochNumberWithFraction::new(100, 0, 1),
        1 => EpochNumberWithFraction::new(300, 0, 1),
        _ => unreachable!(),
    };
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier = TransactionScriptsVerifier::new(&rtx, &consensus, &resource, &tx_env);
    if let Some(debug_printer) = debug_printer {
        verifier.set_debug_printer(debug_printer);
    }
    verifier
        .verify_single(*script_group_type, script_hash, max_cycle)
        .map_err(|err| format!("Verify script error: {:?}", err))
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Debug)]
struct JsonResult {
    cycle: Option<Cycle>,
    error: Option<String>,
}

impl From<Result<Cycle, String>> for JsonResult {
    fn from(result: Result<Cycle, String>) -> JsonResult {
        match result {
            Ok(cycle) => JsonResult {
                cycle: Some(cycle),
                error: None,
            },
            Err(error) => JsonResult {
                cycle: None,
                error: Some(error),
            },
        }
    }
}

fn internal_run_json(
    mock_tx: &str,
    script_group_type: &str,
    hex_script_hash: &str,
    max_cycle: &str,
    debug_printer: Option<Box<dyn Fn(&Byte32, &str)>>,
    version: u32,
) -> Result<Cycle, String> {
    let repr_mock_tx: ReprMockTransaction = from_json_str(mock_tx).map_err(|e| e.to_string())?;
    let mock_tx: MockTransaction = repr_mock_tx.into();
    let script_group_type: ScriptGroupType =
        from_plain_str(script_group_type).map_err(|e| e.to_string())?;
    if hex_script_hash.len() != 66 || (!hex_script_hash.starts_with("0x")) {
        return Err("Invalid script hash format!".to_string());
    }
    let mut b = [0u8; 32];
    hex_decode_fallback(&hex_script_hash.as_bytes()[2..], &mut b[..]);
    let script_hash = Byte32::new(b);
    let max_cycle: Cycle = max_cycle
        .parse()
        .map_err(|_| "Invalid max cycle!".to_string())?;
    run(
        &mock_tx,
        &script_group_type,
        &script_hash,
        max_cycle,
        debug_printer,
        version,
    )
}

#[wasm_bindgen]
pub fn run_json(
    mock_tx: &str,
    script_group_type: &str,
    hex_script_hash: &str,
    max_cycle: &str,
    version: u32,
) -> String {
    let json_result: JsonResult = internal_run_json(
        mock_tx,
        script_group_type,
        hex_script_hash,
        max_cycle,
        None,
        version,
    )
    .into();
    to_json_string(&json_result).expect("JSON serialization should not fail!")
}

#[wasm_bindgen]
pub fn run_json_with_printer(
    mock_tx: &str,
    script_group_type: &str,
    hex_script_hash: &str,
    max_cycle: &str,
    // TODO: not sure if this works, test this or fix ckb-script in next
    // release. We have to pass by value now since debug_priner in ckb-script
    // requires static lifetime, and that wasm_bindgen doesn't support
    // functions with lifetime parameters now.
    debug_printer: JsFunction,
    version: u32,
) -> String {
    let rust_printer = move |hash: &Byte32, message: &str| {
        let mut hex_bytes = [0u8; 64];
        hex_encode_fallback(&hash.as_bytes(), &mut hex_bytes);
        let hex_string = String::from_utf8(hex_bytes.to_vec()).expect("utf8 failiure");
        let hex_string = format!("0x{}", hex_string).to_string();
        debug_printer
            .call2(
                &JsValue::NULL,
                &JsValue::from(&hex_string),
                &JsValue::from(message),
            )
            .expect("debug printer call should work");
    };
    let json_result: JsonResult = internal_run_json(
        mock_tx,
        script_group_type,
        hex_script_hash,
        max_cycle,
        Some(Box::new(rust_printer)),
        version,
    )
    .into();
    to_json_string(&json_result).expect("JSON serialization should not fail!")
}
