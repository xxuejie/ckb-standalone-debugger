use std::fmt::Debug;

use ckb_types::prelude::Entity;

fn analyze(data: &str) -> Result<(), CheckError> {
    let mock: ckb_mock_tx_types::ReprMockTransaction = serde_json::from_str(&data).unwrap();
    analyze_cell_dep(&mock)?;
    analyze_header_dep(&mock)?;
    analyze_input(&mock)?;
    analyze_output(&mock)?;
    Ok(())
}

fn analyze_cell_dep(data: &ckb_mock_tx_types::ReprMockTransaction) -> Result<(), CheckError> {
    let cset: Vec<ckb_jsonrpc_types::CellDep> = data.mock_info.cell_deps.iter().map(|e| e.cell_dep.clone()).collect();
    for (i, e) in data.tx.cell_deps.iter().enumerate() {
        if !cset.contains(&e) {
            let path = vec![Key::Table(String::from("tx")), Key::Table(String::from("cell_deps")), Key::Index(i)];
            return Err(CheckError(format!("Check Fail: {} used unprovided cell dep", keyfmt(&path))));
        }
    }
    let mut ccnt = vec![0u8; cset.len()];
    for (_, e) in data.tx.cell_deps.iter().enumerate() {
        let i = cset.iter().position(|r| r == e).unwrap();
        ccnt[i] += 1;
        if data.mock_info.cell_deps[i].cell_dep.dep_type == ckb_jsonrpc_types::DepType::Code {
            continue;
        }
        let outpoints =
            ckb_types::packed::OutPointVec::from_slice(data.mock_info.cell_deps[i].data.as_bytes()).unwrap();
        let outpoints: Vec<ckb_types::packed::OutPoint> = outpoints.into_iter().collect();
        for (j, f) in outpoints.iter().enumerate() {
            let cdep =
                ckb_jsonrpc_types::CellDep { out_point: f.clone().into(), dep_type: ckb_jsonrpc_types::DepType::Code };
            if !cset.contains(&cdep) {
                let path = vec![
                    Key::Table(String::from("mock_info")),
                    Key::Table(String::from("cell_deps")),
                    Key::Index(i),
                    Key::Table(String::from("data")),
                    Key::Index(j),
                ];
                return Err(CheckError(format!("Check Fail: {} used unprovided cell dep", keyfmt(&path))));
            }
            let k = cset.iter().position(|r| r == &cdep).unwrap();
            ccnt[k] += 1;
        }
    }
    // for (i, e) in ccnt.iter().enumerate() {
    //     if *e != 0 {
    //         continue;
    //     }
    //     let path = vec![Key::Table(String::from("mock_info")), Key::Table(String::from("cell_deps")), Key::Index(i)];
    //     return Err(CheckError(format!("Check Fail: {} unused", keyfmt(&path))));
    // }
    Ok(())
}

fn analyze_header_dep(data: &ckb_mock_tx_types::ReprMockTransaction) -> Result<(), CheckError> {
    let hset: Vec<ckb_types::H256> = data.mock_info.header_deps.iter().map(|e| e.hash.clone()).collect();
    for (i, e) in data.tx.header_deps.iter().enumerate() {
        if !hset.contains(&e) {
            let path = vec![Key::Table(String::from("tx")), Key::Table(String::from("header_deps")), Key::Index(i)];
            return Err(CheckError(format!("Check Fail: {} used unprovided header dep", keyfmt(&path))));
        }
    }
    for (i, e) in hset.iter().enumerate() {
        if !data.tx.header_deps.contains(&e) {
            let path =
                vec![Key::Table(String::from("mock_info")), Key::Table(String::from("header_deps")), Key::Index(i)];
            return Err(CheckError(format!("Check Fail: {} unused", keyfmt(&path))));
        }
    }
    Ok(())
}

fn analyze_input(data: &ckb_mock_tx_types::ReprMockTransaction) -> Result<(), CheckError> {
    let iset: Vec<ckb_jsonrpc_types::CellInput> = data.mock_info.inputs.iter().map(|e| e.input.clone()).collect();
    for (i, e) in data.tx.inputs.iter().enumerate() {
        if !iset.contains(&e) {
            let path = vec![Key::Table(String::from("tx")), Key::Table(String::from("inputs")), Key::Index(i)];
            return Err(CheckError(format!("Check Fail: {} used unprovided input", keyfmt(&path))));
        }
    }
    for (i, e) in iset.iter().enumerate() {
        if !data.tx.inputs.contains(&e) {
            let path = vec![Key::Table(String::from("mock_info")), Key::Table(String::from("inputs")), Key::Index(i)];
            return Err(CheckError(format!("Check Fail: {} unused", keyfmt(&path))));
        }
    }
    Ok(())
}

fn analyze_output(data: &ckb_mock_tx_types::ReprMockTransaction) -> Result<(), CheckError> {
    if data.tx.outputs.len() != data.tx.outputs_data.len() {
        let path = vec![Key::Table(String::from("tx")), Key::Table(String::from("outputs"))];
        return Err(CheckError(format!(
            "Check Fail: {} outputs and outputs_data are not one-to-one correspondence",
            keyfmt(&path)
        )));
    }
    Ok(())
}

/// Analyzes a JSON string representing a mock transaction, validating its structure and dependencies. Returns Ok(())
/// if valid, or a CheckError if validation fails.
pub fn mock_tx_analyze(data: &str) -> Result<(), CheckError> {
    prelude(data)?;
    analyze(data)
}

fn prelude(data: &str) -> Result<(), CheckError> {
    let j: serde_json::Value = serde_json::from_str(data).map_err(|e| CheckError(e.to_string()))?;
    prelude_contains_key(vec![], &j, "mock_info")?;
    prelude_contains_key(vec![], &j, "tx")?;
    prelude_mock_info(keyadd_table(vec![], "mock_info"), j.as_object().unwrap().get("mock_info").unwrap())?;
    prelude_tx(keyadd_table(vec![], "tx"), j.as_object().unwrap().get("tx").unwrap())?;
    Ok(())
}

fn prelude_cell_dep(path: Vec<Key>, data: &serde_json::Value) -> Result<(), CheckError> {
    prelude_contains_key(path.clone(), &data, "out_point")?;
    prelude_contains_key(path.clone(), &data, "dep_type")?;
    prelude_out_point(keyadd_table(path.clone(), "out_point"), data.as_object().unwrap().get("out_point").unwrap())?;
    prelude_dep_type(keyadd_table(path.clone(), "dep_type"), data.as_object().unwrap().get("dep_type").unwrap())?;
    Ok(())
}

fn prelude_contains_key(path: Vec<Key>, data: &serde_json::Value, key: &str) -> Result<(), CheckError> {
    if !data.is_object() {
        return Err(CheckError(format!("Check Fail: {} is not an object", keyfmt(&path))));
    }
    if !data.as_object().unwrap().contains_key(key) {
        return Err(CheckError(format!("Check Fail: {} missing members: {}", keyfmt(&path), key)));
    }
    Ok(())
}

fn prelude_dep_type(path: Vec<Key>, data: &serde_json::Value) -> Result<(), CheckError> {
    if !data.is_string() {
        return Err(CheckError(format!("Check Fail: {} {}", keyfmt(&path), "is not a legal dep type")));
    }
    if serde_json::from_str::<ckb_jsonrpc_types::DepType>(&format!("{:?}", &data.as_str().unwrap())).is_err() {
        return Err(CheckError(format!("Check Fail: {} {}", keyfmt(&path), "is not a legal dep type")));
    }
    Ok(())
}

fn prelude_hash(path: Vec<Key>, data: &serde_json::Value) -> Result<(), CheckError> {
    prelude_hex(path.clone(), data)?;
    if data.as_str().unwrap().len() != 66 {
        return Err(CheckError(format!("Check Fail: {} {}", keyfmt(&path), "is not a legal hash")));
    }
    Ok(())
}

fn prelude_hash_type(path: Vec<Key>, data: &serde_json::Value) -> Result<(), CheckError> {
    if !data.is_string() {
        return Err(CheckError(format!("Check Fail: {} {}", keyfmt(&path), "is not a legal hash type")));
    }
    if serde_json::from_str::<ckb_jsonrpc_types::ScriptHashType>(&format!("{:?}", &data.as_str().unwrap())).is_err() {
        return Err(CheckError(format!("Check Fail: {} {}", keyfmt(&path), "is not a legal hash type")));
    }
    Ok(())
}

fn prelude_hex(path: Vec<Key>, data: &serde_json::Value) -> Result<(), CheckError> {
    if !data.is_string() {
        return Err(CheckError(format!("Check Fail: {} {}", keyfmt(&path), "is not a legal hex string")));
    }
    if !data.as_str().unwrap().starts_with("0x") {
        return Err(CheckError(format!("Check Fail: {} {}", keyfmt(&path), "is not a legal hex string")));
    }
    if hex::decode(&data.as_str().unwrap()[2..]).is_err() {
        return Err(CheckError(format!("Check Fail: {} {}", keyfmt(&path), "is not a legal hex string")));
    }
    Ok(())
}

fn prelude_input(path: Vec<Key>, data: &serde_json::Value) -> Result<(), CheckError> {
    prelude_contains_key(path.clone(), &data, "since")?;
    prelude_contains_key(path.clone(), &data, "previous_output")?;
    prelude_u64(keyadd_table(path.clone(), "since"), data.as_object().unwrap().get("since").unwrap())?;
    prelude_out_point(
        keyadd_table(path.clone(), "previous_output"),
        data.as_object().unwrap().get("previous_output").unwrap(),
    )?;
    Ok(())
}

fn prelude_mock_info(path: Vec<Key>, data: &serde_json::Value) -> Result<(), CheckError> {
    prelude_contains_key(path.clone(), &data, "inputs")?;
    prelude_contains_key(path.clone(), &data, "cell_deps")?;
    prelude_contains_key(path.clone(), &data, "header_deps")?;
    for (i, e) in data.as_object().unwrap().get("inputs").unwrap().as_array().unwrap().iter().enumerate() {
        let path = keyadd_index(keyadd_table(path.clone(), "inputs"), i);
        prelude_contains_key(path.clone(), e, "input")?;
        prelude_contains_key(path.clone(), e, "output")?;
        prelude_contains_key(path.clone(), e, "data")?;
        prelude_input(keyadd_table(path.clone(), "input"), e.as_object().unwrap().get("input").unwrap())?;
        prelude_output(keyadd_table(path.clone(), "output"), e.as_object().unwrap().get("output").unwrap())?;
        prelude_hex(keyadd_table(path.clone(), "data"), e.as_object().unwrap().get("data").unwrap())?;
        if e.as_object().unwrap().contains_key("header") && !e.as_object().unwrap().get("header").unwrap().is_null() {
            prelude_hash(keyadd_table(path.clone(), "header"), e.as_object().unwrap().get("header").unwrap())?;
        }
    }
    for (i, e) in data.as_object().unwrap().get("cell_deps").unwrap().as_array().unwrap().iter().enumerate() {
        let path = keyadd_index(keyadd_table(path.clone(), "cell_deps"), i);
        prelude_contains_key(path.clone(), e, "cell_dep")?;
        prelude_contains_key(path.clone(), e, "output")?;
        prelude_contains_key(path.clone(), e, "data")?;
        prelude_cell_dep(keyadd_table(path.clone(), "cell_dep"), e.as_object().unwrap().get("cell_dep").unwrap())?;
        prelude_output(keyadd_table(path.clone(), "output"), e.as_object().unwrap().get("output").unwrap())?;
        prelude_hex(keyadd_table(path.clone(), "data"), e.as_object().unwrap().get("data").unwrap())?;
        if e.as_object().unwrap().contains_key("header") && !e.as_object().unwrap().get("header").unwrap().is_null() {
            prelude_hash(keyadd_table(path.clone(), "header"), e.as_object().unwrap().get("header").unwrap())?;
        }
    }
    for (i, e) in data.as_object().unwrap().get("header_deps").unwrap().as_array().unwrap().iter().enumerate() {
        let path = keyadd_index(keyadd_table(path.clone(), "header_deps"), i);
        prelude_contains_key(path.clone(), e, "compact_target")?;
        prelude_contains_key(path.clone(), e, "dao")?;
        prelude_contains_key(path.clone(), e, "epoch")?;
        prelude_contains_key(path.clone(), e, "extra_hash")?;
        prelude_contains_key(path.clone(), e, "hash")?;
        prelude_contains_key(path.clone(), e, "nonce")?;
        prelude_contains_key(path.clone(), e, "number")?;
        prelude_contains_key(path.clone(), e, "parent_hash")?;
        prelude_contains_key(path.clone(), e, "proposals_hash")?;
        prelude_contains_key(path.clone(), e, "timestamp")?;
        prelude_contains_key(path.clone(), e, "transactions_root")?;
        prelude_contains_key(path.clone(), e, "version")?;
        prelude_u32(
            keyadd_table(path.clone(), "compact_target"),
            e.as_object().unwrap().get("compact_target").unwrap(),
        )?;
        prelude_hash(keyadd_table(path.clone(), "dao"), e.as_object().unwrap().get("dao").unwrap())?;
        prelude_u64(keyadd_table(path.clone(), "epoch"), e.as_object().unwrap().get("epoch").unwrap())?;
        prelude_hash(keyadd_table(path.clone(), "extra_hash"), e.as_object().unwrap().get("extra_hash").unwrap())?;
        prelude_hash(keyadd_table(path.clone(), "hash"), e.as_object().unwrap().get("hash").unwrap())?;
        prelude_u128(keyadd_table(path.clone(), "nonce"), e.as_object().unwrap().get("nonce").unwrap())?;
        prelude_u64(keyadd_table(path.clone(), "number"), e.as_object().unwrap().get("number").unwrap())?;
        prelude_hash(keyadd_table(path.clone(), "parent_hash"), e.as_object().unwrap().get("parent_hash").unwrap())?;
        prelude_hash(
            keyadd_table(path.clone(), "proposals_hash"),
            e.as_object().unwrap().get("proposals_hash").unwrap(),
        )?;
        prelude_u64(keyadd_table(path.clone(), "timestamp"), e.as_object().unwrap().get("timestamp").unwrap())?;
        prelude_hash(
            keyadd_table(path.clone(), "transactions_root"),
            e.as_object().unwrap().get("transactions_root").unwrap(),
        )?;
        prelude_u32(keyadd_table(path.clone(), "version"), e.as_object().unwrap().get("version").unwrap())?;
    }
    Ok(())
}

fn prelude_out_point(path: Vec<Key>, data: &serde_json::Value) -> Result<(), CheckError> {
    prelude_contains_key(path.clone(), data, "tx_hash")?;
    prelude_contains_key(path.clone(), data, "index")?;
    prelude_hash(keyadd_table(path.clone(), "tx_hash"), data.as_object().unwrap().get("tx_hash").unwrap())?;
    prelude_u32(keyadd_table(path.clone(), "index"), data.as_object().unwrap().get("index").unwrap())?;
    Ok(())
}

fn prelude_output(path: Vec<Key>, data: &serde_json::Value) -> Result<(), CheckError> {
    prelude_contains_key(path.clone(), data, "capacity")?;
    prelude_contains_key(path.clone(), data, "lock")?;
    prelude_u64(keyadd_table(path.clone(), "capacity"), data.as_object().unwrap().get("capacity").unwrap())?;
    prelude_script(keyadd_table(path.clone(), "lock"), data.as_object().unwrap().get("lock").unwrap())?;
    if data.as_object().unwrap().contains_key("type") && !data.as_object().unwrap().get("type").unwrap().is_null() {
        prelude_script(keyadd_table(path.clone(), "type"), data.as_object().unwrap().get("type").unwrap())?;
    }
    Ok(())
}

fn prelude_script(path: Vec<Key>, data: &serde_json::Value) -> Result<(), CheckError> {
    prelude_contains_key(path.clone(), data, "code_hash")?;
    prelude_contains_key(path.clone(), data, "hash_type")?;
    prelude_contains_key(path.clone(), data, "args")?;
    prelude_hash(keyadd_table(path.clone(), "code_hash"), data.as_object().unwrap().get("code_hash").unwrap())?;
    prelude_hash_type(keyadd_table(path.clone(), "hash_type"), data.as_object().unwrap().get("hash_type").unwrap())?;
    prelude_hex(keyadd_table(path.clone(), "args"), data.as_object().unwrap().get("args").unwrap())?;
    Ok(())
}

fn prelude_tx(path: Vec<Key>, data: &serde_json::Value) -> Result<(), CheckError> {
    prelude_contains_key(path.clone(), &data, "version")?;
    prelude_contains_key(path.clone(), &data, "cell_deps")?;
    prelude_contains_key(path.clone(), &data, "header_deps")?;
    prelude_contains_key(path.clone(), &data, "inputs")?;
    prelude_contains_key(path.clone(), &data, "outputs")?;
    prelude_contains_key(path.clone(), &data, "outputs_data")?;
    prelude_contains_key(path.clone(), &data, "witnesses")?;
    prelude_u32(keyadd_table(path.clone(), "version"), data.as_object().unwrap().get("version").unwrap())?;
    for (i, e) in data.as_object().unwrap().get("cell_deps").unwrap().as_array().unwrap().iter().enumerate() {
        let path = keyadd_index(keyadd_table(path.clone(), "cell_deps"), i);
        prelude_cell_dep(path, e)?;
    }
    for (i, e) in data.as_object().unwrap().get("header_deps").unwrap().as_array().unwrap().iter().enumerate() {
        let path = keyadd_index(keyadd_table(path.clone(), "header_deps"), i);
        prelude_hash(path, e)?;
    }
    for (i, e) in data.as_object().unwrap().get("inputs").unwrap().as_array().unwrap().iter().enumerate() {
        let path = keyadd_index(keyadd_table(path.clone(), "inputs"), i);
        prelude_input(path, e)?;
    }
    for (i, e) in data.as_object().unwrap().get("outputs").unwrap().as_array().unwrap().iter().enumerate() {
        let path = keyadd_index(keyadd_table(path.clone(), "outputs"), i);
        prelude_output(path, e)?;
    }
    for (i, e) in data.as_object().unwrap().get("outputs_data").unwrap().as_array().unwrap().iter().enumerate() {
        let path = keyadd_index(keyadd_table(path.clone(), "outputs_data"), i);
        prelude_hex(path, e)?;
    }
    for (i, e) in data.as_object().unwrap().get("witnesses").unwrap().as_array().unwrap().iter().enumerate() {
        let path = keyadd_index(keyadd_table(path.clone(), "witnesses"), i);
        prelude_hex(path, e)?;
    }
    Ok(())
}

fn prelude_u128(path: Vec<Key>, data: &serde_json::Value) -> Result<(), CheckError> {
    if !data.is_string() || !data.as_str().unwrap().starts_with("0x") {
        return Err(CheckError(format!("Check Fail: {} {}", keyfmt(&path), "is not a legal u128")));
    }
    if u128::from_str_radix(&data.as_str().unwrap()[2..], 16).is_err() {
        return Err(CheckError(format!("Check Fail: {} {}", keyfmt(&path), "is not a legal u128")));
    }
    Ok(())
}

fn prelude_u32(path: Vec<Key>, data: &serde_json::Value) -> Result<(), CheckError> {
    if !data.is_string() || !data.as_str().unwrap().starts_with("0x") {
        return Err(CheckError(format!("Check Fail: {} {}", keyfmt(&path), "is not a legal u32")));
    }
    if u32::from_str_radix(&data.as_str().unwrap()[2..], 16).is_err() {
        return Err(CheckError(format!("Check Fail: {} {}", keyfmt(&path), "is not a legal u32")));
    }
    Ok(())
}

fn prelude_u64(path: Vec<Key>, data: &serde_json::Value) -> Result<(), CheckError> {
    if !data.is_string() || !data.as_str().unwrap().starts_with("0x") {
        return Err(CheckError(format!("Check Fail: {} {}", keyfmt(&path), "is not a legal u64")));
    }
    if u64::from_str_radix(&data.as_str().unwrap()[2..], 16).is_err() {
        return Err(CheckError(format!("Check Fail: {} {}", keyfmt(&path), "is not a legal u64")));
    }
    Ok(())
}

pub struct CheckError(String);

impl std::fmt::Debug for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::fmt::Display for CheckError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CheckError {}

#[derive(Clone, Debug)]
enum Key {
    Table(String),
    Index(usize),
}

fn keyfmt(key: &[Key]) -> String {
    let mut s = String::from("json");
    for e in key {
        match e {
            Key::Table(k) => {
                s.push_str(&format!("[\"{}\"]", k));
            }
            Key::Index(i) => {
                s.push_str(&format!("[{}]", i));
            }
        }
    }
    s
}

fn keyadd_index(mut key: Vec<Key>, add: usize) -> Vec<Key> {
    key.push(Key::Index(add));
    key
}

fn keyadd_table(mut key: Vec<Key>, add: &str) -> Vec<Key> {
    key.push(Key::Table(String::from(add)));
    key
}
