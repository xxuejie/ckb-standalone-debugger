use byteorder::{ByteOrder, LittleEndian};
use ckb_script::ScriptGroupType;
use ckb_standalone_debugger::{
    run,
    transaction::{MockCellDep, MockInfo, MockInput, MockTransaction},
};
use ckb_types::{
    bytes::Bytes,
    core::{Capacity, DepType, ScriptHashType, TransactionBuilder},
    packed::{self, Byte32, CellDep, CellInput, CellOutput, OutPoint, Script},
    prelude::*,
};
use std::fs::File;
use std::io::Read;

fn read_file(name: &str) -> Bytes {
    let mut file = File::open(name).unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();
    buffer.into()
}

fn create_mock_cell_dep(data: Bytes, lock: Option<Script>) -> (Byte32, MockCellDep) {
    let hash = CellOutput::calc_data_hash(&data);
    let hash2 = CellOutput::calc_data_hash(hash.as_slice());
    let out_point = OutPoint::new_builder().tx_hash(hash2).build();
    let cell_dep = CellDep::new_builder()
        .out_point(out_point)
        .dep_type(DepType::Code.into())
        .build();
    let cell_output = CellOutput::new_builder()
        .capacity(Capacity::bytes(data.len() + 200).unwrap().pack())
        .lock(lock.unwrap_or_else(Script::default))
        .build();
    (
        hash,
        MockCellDep {
            cell_dep,
            output: cell_output,
            data,
            header: None,
        },
    )
}

#[test]
pub fn test_bench() {
    let data = read_file("tests/programs/bench.c");
    let code = read_file("tests/programs/bench");
    let mut script_args = [0u8; 32];
    LittleEndian::write_u64(&mut script_args[0..8], 100);
    LittleEndian::write_u64(&mut script_args[8..16], 100);
    LittleEndian::write_u64(&mut script_args[16..24], 100);
    LittleEndian::write_u64(&mut script_args[24..32], 100);
    let script_args: packed::Bytes = script_args[..].pack();
    let (_, data_dep) = create_mock_cell_dep(data, None);
    let (code_hash, code_dep) = create_mock_cell_dep(code, None);

    let script = Script::new_builder()
        .code_hash(code_hash.clone())
        .hash_type(ScriptHashType::Data.into())
        .args(script_args)
        .build();
    let (_, input_dep) = create_mock_cell_dep(Bytes::from("abc"), Some(script));
    let script_hash = input_dep.output.calc_lock_hash();
    let cell_input = CellInput::new_builder()
        .previous_output(input_dep.cell_dep.out_point())
        .build();
    let cell_output = CellOutput::new_builder().build();
    let transaction = TransactionBuilder::default()
        .input(cell_input.clone())
        .output(cell_output)
        .witness(packed::Bytes::default())
        .output_data(packed::Bytes::default())
        .cell_dep(data_dep.cell_dep.clone())
        .cell_dep(code_dep.cell_dep.clone())
        .build();
    let mock_input = MockInput {
        input: cell_input,
        output: input_dep.output,
        data: input_dep.data,
        header: None,
    };
    let mock_info = MockInfo {
        inputs: vec![mock_input],
        cell_deps: vec![data_dep, code_dep],
        header_deps: vec![],
    };
    let mock_transaction = MockTransaction {
        mock_info,
        tx: transaction.data(),
    };

    let result = run(
        &mock_transaction,
        &ScriptGroupType::Lock,
        &script_hash,
        20_000_000,
        None,
        0,
    );
    assert_eq!(result.unwrap(), 58897);
}
