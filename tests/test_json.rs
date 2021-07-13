use ckb_standalone_debugger::run_json;
use std::fs::read_to_string;

#[test]
pub fn test_sample_json() {
    let mock_tx = read_to_string("tests/programs/sample.json").unwrap();
    let result = run_json(
        &mock_tx,
        "type",
        "0xee75995da2e55e6c4938533d341597bc10add3837cfe57174f2ee755da82555c",
        "4000",
        0,
    );
    assert_eq!(result, "{\"cycle\":3217,\"error\":null}");
}

#[test]
pub fn test_sample_json_version1() {
    let mock_tx = read_to_string("tests/programs/sample_data1.json").unwrap();
    let result = run_json(
        &mock_tx,
        "type",
        "0xca505bee92c34ac4522d15da2c91f0e4060e4540f90a28d7202df8fe8ce930ba",
        "4000",
        1,
    );
    assert_eq!(result, "{\"cycle\":3219,\"error\":null}");
}
