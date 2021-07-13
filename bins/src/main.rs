#[macro_use]
extern crate log;

use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_script::{
    cost_model::transferred_byte_cycles, ScriptGroupType, ScriptVersion,
    TransactionScriptsVerifier, TxVerifyEnv,
};
use ckb_standalone_debugger::{
    transaction::{MockTransaction, ReprMockTransaction, Resource},
    DummyResourceLoader,
};
use ckb_types::{
    core::{
        cell::resolve_transaction, hardfork::HardForkSwitch, Cycle, EpochNumberWithFraction,
        HeaderView,
    },
    packed::Byte32,
    prelude::Pack,
};
use ckb_vm::{
    decoder::build_decoder,
    machine::asm::{AsmCoreMachine, AsmMachine},
    CoreMachine, DefaultMachineBuilder, SupportMachine,
};
use ckb_vm_debug_utils::{ElfDumper, GdbHandler, Stdio};
use clap::{crate_version, App, Arg};
use faster_hex::hex_decode_fallback;
use gdb_remote_protocol::process_packets_from;
use serde_json::from_str as from_json_str;
use serde_plain::from_str as from_plain_str;
use std::collections::HashSet;
use std::fs::{read, read_to_string};
use std::net::TcpListener;

fn main() {
    drop(env_logger::init());
    let default_max_cycles = format!("{}", 70_000_000u64);
    let matches = App::new("ckb-debugger")
        .version(crate_version!())
        .arg(
            Arg::with_name("listen")
                .short("l")
                .long("listen")
                .help("Address to listen for GDB remote debugging server")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("tx-file")
                .short("t")
                .long("tx-file")
                .required(true)
                .help("Filename containing JSON formatted transaction dump")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("script-group-type")
                .short("g")
                .long("script-group-type")
                .required(true)
                .possible_values(&["lock", "type"])
                .help("Script group type")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("script-hash")
                .short("h")
                .long("script-hash")
                .help("Script hash")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cell-type")
                .short("e")
                .long("cell-type")
                .possible_values(&["input", "output"])
                .help("Type of cell to run")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("cell-index")
                .short("i")
                .long("cell-index")
                .help("Index of cell to run")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("max-cycle")
                .short("c")
                .long("max-cycle")
                .default_value(&default_max_cycles)
                .help("Max cycles")
                .takes_value(true),
        )
        .arg(Arg::with_name("step").short("s").long("step").multiple(true).help(
            "Set to true to enable step mode, where we print PC address for each instruction",
        ))
        .arg(
            Arg::with_name("skip-start")
                .long("skip-start")
                .help("Start address to skip printing debug info")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("skip-end")
                .long("skip-end")
                .help("End address to skip printing debug info")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("dump-file")
                .short("d")
                .long("dump-file")
                .help("Dump file name")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("replace-binary")
                .short("r")
                .long("replace-binary")
                .help("File used to replace the binary denoted in the script")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("script-version")
                .long("script-version")
                .help("Script version")
                .takes_value(true),
        )
        .get_matches();

    let filename = matches.value_of("tx-file").unwrap();
    let mock_tx = read_to_string(&filename).expect("open tx file");
    let repr_mock_tx: ReprMockTransaction = from_json_str(&mock_tx).expect("parse tx file");
    let mock_tx: MockTransaction = repr_mock_tx.into();
    let script_group_type = matches.value_of("script-group-type").unwrap();
    let script_group_type: ScriptGroupType =
        from_plain_str(script_group_type).expect("parse script group type");
    let script_hash = if let Some(hex_script_hash) = matches.value_of("script-hash") {
        if hex_script_hash.len() != 66 || (!hex_script_hash.starts_with("0x")) {
            panic!("Invalid script hash format!");
        }
        let mut b = [0u8; 32];
        hex_decode_fallback(&hex_script_hash.as_bytes()[2..], &mut b[..]);
        Byte32::new(b)
    } else {
        let cell_type = matches.value_of("cell-type");
        let cell_index = matches.value_of("cell-index");
        if cell_type.is_none() || cell_index.is_none() {
            panic!("You must provide either script hash, or cell type + cell index");
        }
        let cell_type = cell_type.unwrap();
        let cell_index: usize = cell_index.unwrap().parse().expect("parse cell index");
        match (&script_group_type, cell_type) {
            (ScriptGroupType::Lock, "input") => {
                mock_tx.mock_info.inputs[cell_index].output.calc_lock_hash()
            }
            (ScriptGroupType::Type, "input") => mock_tx.mock_info.inputs[cell_index]
                .output
                .type_()
                .to_opt()
                .expect("cell should have type script")
                .calc_script_hash(),
            (ScriptGroupType::Type, "output") => mock_tx
                .tx
                .raw()
                .outputs()
                .get(cell_index)
                .expect("index out of bound")
                .type_()
                .to_opt()
                .expect("cell should have type script")
                .calc_script_hash(),
            _ => panic!(
                "Invalid specified script: {:?} {} {}",
                script_group_type, cell_type, cell_index
            ),
        }
    };
    let max_cycle: Cycle = matches
        .value_of("max-cycle")
        .unwrap()
        .parse()
        .expect("parse max cycle");

    let script_version_u32: u32 = matches
        .value_of("script-version")
        .unwrap()
        .parse()
        .expect("parse vm version");
    let script_version = if script_version_u32 == 0u32 {
        ScriptVersion::V0
    } else {
        ScriptVersion::V1
    };

    let resource = Resource::from_both(&mock_tx, DummyResourceLoader {}).expect("load resource");
    let tx = mock_tx.core_transaction();
    let rtx = {
        let mut seen_inputs = HashSet::new();
        resolve_transaction(tx, &mut seen_inputs, &resource, &resource)
            .expect("resolve transaction")
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
    let epoch = match script_version {
        ScriptVersion::V0 => EpochNumberWithFraction::new(100, 0, 1),
        ScriptVersion::V1 => EpochNumberWithFraction::new(300, 0, 1),
    };
    let tx_env = {
        let header = HeaderView::new_advanced_builder()
            .epoch(epoch.pack())
            .build();
        TxVerifyEnv::new_commit(&header)
    };
    let mut verifier = TransactionScriptsVerifier::new(&rtx, &consensus, &resource, &tx_env);
    verifier.set_debug_printer(Box::new(|hash: &Byte32, message: &str| {
        debug!("script group: {} DEBUG OUTPUT: {}", hash, message);
    }));

    let script_group = verifier
        .find_script_group(script_group_type, &script_hash)
        .expect("find script group");
    let mut program = verifier
        .extract_script(&script_group.script)
        .expect("extract script");
    if let Some(replace_file) = matches.value_of("replace-binary") {
        let data = read(replace_file).expect("read binary file");
        program = data.into();
    }

    if let Some(listen_address) = matches.value_of("listen") {
        // GDB path
        let listener = TcpListener::bind(listen_address).expect("listen");
        debug!("Listening on {}", listen_address);

        for res in listener.incoming() {
            debug!("Got connection");
            if let Ok(stream) = res {
                let core_machine = AsmCoreMachine::new(
                    script_version.vm_isa(),
                    script_version.vm_version(),
                    max_cycle,
                );
                let builder = DefaultMachineBuilder::new(core_machine)
                    .instruction_cycle_func(verifier.cost_model())
                    .syscall(Box::new(Stdio::new(true)));
                let builder = verifier
                    .generate_syscalls(script_version, script_group)
                    .into_iter()
                    .fold(builder, |builder, syscall| builder.syscall(syscall));
                let mut machine = AsmMachine::new(builder.build(), None);
                let bytes = machine.load_program(&program, &[]).expect("load program");
                machine
                    .machine
                    .add_cycles(transferred_byte_cycles(bytes))
                    .expect("load program cycles");
                machine.machine.set_running(true);
                let h = GdbHandler::new(machine);
                process_packets_from(stream.try_clone().unwrap(), stream, h);
            }
            debug!("Connection closed");
        }
    } else {
        // Single run path
        let core_machine = AsmCoreMachine::new(
            script_version.vm_isa(),
            script_version.vm_version(),
            max_cycle,
        );
        let mut builder = DefaultMachineBuilder::new(core_machine)
            .instruction_cycle_func(verifier.cost_model())
            .syscall(Box::new(Stdio::new(false)));
        if let Some(dump_file_name) = matches.value_of("dump-file") {
            builder = builder.syscall(Box::new(ElfDumper::new(
                dump_file_name.to_string(),
                4097,
                64,
            )));
        }
        let builder = verifier
            .generate_syscalls(script_version, script_group)
            .into_iter()
            .fold(builder, |builder, syscall| builder.syscall(syscall));
        let mut machine = AsmMachine::new(builder.build(), None);
        let bytes = machine.load_program(&program, &[]).expect("load program");
        let transferred_cycles = transferred_byte_cycles(bytes);
        machine
            .machine
            .add_cycles(transferred_cycles)
            .expect("load program cycles");
        let result = if matches.occurrences_of("step") > 0 {
            machine.machine.set_running(true);
            let decoder = build_decoder::<u64>(script_version.vm_isa());
            let mut step_result = Ok(());
            let skip_range = if let (Some(s), Some(e)) =
                (matches.value_of("skip-start"), matches.value_of("skip-end"))
            {
                let s =
                    u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("parse skip start");
                let e =
                    u64::from_str_radix(e.trim_start_matches("0x"), 16).expect("parse skip end");
                Some(std::ops::Range { start: s, end: e })
            } else {
                None
            };
            while machine.machine.running() && step_result.is_ok() {
                let mut print_info = true;
                if let Some(skip_range) = &skip_range {
                    if skip_range.contains(machine.machine.pc()) {
                        print_info = false;
                    }
                }
                if print_info {
                    println!("PC: 0x{:x}", machine.machine.pc());
                    if matches.occurrences_of("step") > 1 {
                        println!("Machine: {}", machine.machine);
                    }
                }
                step_result = machine.machine.step(&decoder);
            }
            if step_result.is_err() {
                Err(step_result.unwrap_err())
            } else {
                Ok(machine.machine.exit_code())
            }
        } else {
            machine.run()
        };
        println!(
            "Run result: {:?}\nTotal cycles consumed: {}\nTransfer cycles: {}, running cycles: {}\n",
            result,
            machine.machine.cycles(),
            transferred_cycles,
            machine.machine.cycles() - transferred_cycles,
        );
        if result.is_err() {
            println!("Machine status: {}", machine.machine);
        }
    }
}
