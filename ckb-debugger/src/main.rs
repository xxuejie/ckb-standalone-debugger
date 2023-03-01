#[macro_use]
extern crate log;

use ckb_debugger_api::DummyResourceLoader;
use ckb_mock_tx_types::{MockTransaction, ReprMockTransaction, Resource};
use ckb_script::{
    cost_model::{instruction_cycles, transferred_byte_cycles},
    ScriptGroupType, ScriptVersion, TransactionScriptsVerifier,
};
use ckb_types::{core::cell::resolve_transaction, packed::Byte32};
use ckb_vm::{
    decoder::build_decoder, Bytes, CoreMachine, DefaultCoreMachine, DefaultMachineBuilder, SupportMachine, WXorXMemory,
};
#[cfg(feature = "stdio")]
use ckb_vm_debug_utils::Stdio;
use ckb_vm_debug_utils::{ElfDumper, GdbHandler};
use ckb_vm_pprof::{PProfMachine, Profile};
use clap::{crate_version, App, Arg};
use faster_hex::hex_decode_fallback;
use gdb_remote_protocol::process_packets_from;
use serde_json::from_str as from_json_str;
use serde_plain::from_str as from_plain_str;
use std::collections::HashSet;
use std::fs::{read, read_to_string};
use std::net::TcpListener;
mod misc;
use misc::{FileOperation, FileStream, HumanReadableCycles, Random, TimeNow};

#[cfg(feature = "probes")]
type MemoryType = ckb_vm::FlatMemory<u64>;
#[cfg(not(feature = "probes"))]
type MemoryType = ckb_vm::SparseMemory<u64>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    drop(env_logger::init());

    let default_max_cycles = format!("{}", 70_000_000u64);
    let default_script_version = "1";
    let default_mode = "full";

    let matches = App::new("ckb-debugger")
        .version(crate_version!())
        .arg(
            Arg::with_name("bin")
                .long("bin")
                .help("File used to replace the binary denoted in the script")
                .takes_value(true),
        )
        .arg(Arg::with_name("cell-index").long("cell-index").help("Index of cell to run").takes_value(true))
        .arg(
            Arg::with_name("cell-type")
                .long("cell-type")
                .possible_values(&["input", "output"])
                .help("Type of cell to run")
                .takes_value(true),
        )
        .arg(Arg::with_name("dump-file").long("dump-file").help("Dump file name").takes_value(true))
        .arg(
            Arg::with_name("gdb-listen")
                .long("gdb-listen")
                .help("Address to listen for GDB remote debugging server")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("max-cycles")
                .long("max-cycles")
                .default_value(&default_max_cycles)
                .help("Max cycles")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("mode")
                .long("mode")
                .help("Execution mode of debugger")
                .possible_values(&["full", "fast", "gdb", "probe"])
                .default_value(&default_mode)
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("pprof")
                .long("pprof")
                .help("Performance profiling, specify output file for further use")
                .takes_value(true),
        )
        .arg(Arg::with_name("script-hash").long("script-hash").help("Script hash").takes_value(true))
        .arg(
            Arg::with_name("script-group-type")
                .long("script-group-type")
                .possible_values(&["lock", "type"])
                .help("Script group type")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("script-version")
                .long("script-version")
                .default_value(&default_script_version)
                .help("Script version")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("skip-end")
                .long("skip-end")
                .help("End address to skip printing debug info")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("skip-start")
                .long("skip-start")
                .help("Start address to skip printing debug info")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("step")
                .long("step")
                .multiple(true)
                .help("Set to true to enable step mode, where we print PC address for each instruction"),
        )
        .arg(
            Arg::with_name("tx-file")
                .long("tx-file")
                .required_unless("bin")
                .help("Filename containing JSON formatted transaction dump")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("read-file")
                .long("read-file")
                .help("Read content from local file or stdin. Then feed the content to syscall in scripts")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("long-log")
                .long("long-log")
                .required(false)
                .takes_value(false)
                .help("long log message with script group"),
        )
        .arg(Arg::with_name("args").multiple(true))
        .get_matches();

    let matches_bin = matches.value_of("bin");
    let matches_cell_index = matches.value_of("cell-index");
    let matches_cell_type = matches.value_of("cell-type");
    let matches_pprof = matches.value_of("pprof");
    let matches_dump_file = matches.value_of("dump-file");
    let matches_gdb_listen = matches.value_of("gdb-listen");
    let matches_max_cycles = matches.value_of("max-cycles").unwrap();
    let matches_mode = matches.value_of("mode").unwrap();
    let matches_script_hash = matches.value_of("script-hash");
    let matches_script_group_type = matches.value_of("script-group-type");
    let matches_script_version = matches.value_of("script-version").unwrap();
    let matches_skip_end = matches.value_of("skip-end");
    let matches_skip_start = matches.value_of("skip-start");
    let matches_step = matches.occurrences_of("step");
    let matches_tx_file = matches.value_of("tx-file");
    let matches_args = matches.values_of("args").unwrap_or_default();
    let read_file_name = matches.value_of("read-file");
    let long_log = matches.is_present("long-log");

    let verifier_args: Vec<String> = matches_args.into_iter().map(|s| s.clone().into()).collect();
    let verifier_args_byte: Vec<Bytes> = verifier_args.into_iter().map(|s| s.into()).collect();

    let fs_syscall = if let Some(file_name) = read_file_name {
        Some(FileStream::new(file_name))
    } else {
        None
    };

    let verifier_max_cycles: u64 = matches_max_cycles.parse()?;
    let verifier_mock_tx: MockTransaction = {
        let mock_tx = if matches_tx_file.is_none() {
            String::from_utf8_lossy(include_bytes!("./dummy_tx.json")).to_string()
        } else {
            read_to_string(matches_tx_file.unwrap())?
        };
        let repr_mock_tx: ReprMockTransaction = from_json_str(&mock_tx)?;
        repr_mock_tx.into()
    };
    let verifier_script_group_type = {
        let script_group_type = if matches_tx_file.is_none() {
            "type"
        } else {
            matches_script_group_type.unwrap()
        };
        from_plain_str(script_group_type)?
    };
    let verifier_script_hash = if matches_tx_file.is_none() {
        let mut b = [0u8; 32];
        hex_decode_fallback(
            b"8f59e340cfbea088720265cef0fd9afa4e420bf27c7b3dc8aebf6c6eda453e57",
            &mut b[..],
        );
        Byte32::new(b)
    } else if let Some(hex_script_hash) = matches_script_hash {
        if hex_script_hash.len() != 66 || (!hex_script_hash.starts_with("0x")) {
            panic!("Invalid script hash format!");
        }
        let mut b = [0u8; 32];
        hex_decode_fallback(&hex_script_hash.as_bytes()[2..], &mut b[..]);
        Byte32::new(b)
    } else {
        let cell_type = matches_cell_type;
        let cell_index = matches_cell_index;
        if cell_type.is_none() || cell_index.is_none() {
            panic!("You must provide either script hash, or cell type + cell index");
        }
        let cell_type = cell_type.unwrap();
        let cell_index: usize = cell_index.unwrap().parse()?;
        match (&verifier_script_group_type, cell_type) {
            (ScriptGroupType::Lock, "input") => verifier_mock_tx.mock_info.inputs[cell_index].output.calc_lock_hash(),
            (ScriptGroupType::Type, "input") => verifier_mock_tx.mock_info.inputs[cell_index]
                .output
                .type_()
                .to_opt()
                .expect("cell should have type script")
                .calc_script_hash(),
            (ScriptGroupType::Type, "output") => verifier_mock_tx
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
                verifier_script_group_type, cell_type, cell_index
            ),
        }
    };
    let verifier_script_version = match matches_script_version {
        "0" => ScriptVersion::V0,
        "1" => ScriptVersion::V1,
        _ => panic!("wrong script version"),
    };
    let verifier_resource = Resource::from_both(&verifier_mock_tx, DummyResourceLoader {})?;
    let verifier_resolve_transaction = resolve_transaction(
        verifier_mock_tx.core_transaction(),
        &mut HashSet::new(),
        &verifier_resource,
        &verifier_resource,
    )?;
    let mut verifier = TransactionScriptsVerifier::new(&verifier_resolve_transaction, &verifier_resource);
    verifier.set_debug_printer(Box::new(move |hash: &Byte32, message: &str| {
        if long_log {
            debug!("script group: {} DEBUG OUTPUT: {}", hash, message);
        } else {
            debug!("SCRIPT>{}", message);
        }
    }));
    let verifier_script_group = verifier.find_script_group(verifier_script_group_type, &verifier_script_hash).unwrap();
    let verifier_program = match matches_bin {
        Some(path) => {
            let data = read(path)?;
            data.into()
        }
        None => verifier.extract_script(&verifier_script_group.script)?,
    };

    let machine_init = || {
        let machine_core = DefaultCoreMachine::<u64, WXorXMemory<MemoryType>>::new(
            verifier_script_version.vm_isa(),
            verifier_script_version.vm_version(),
            verifier_max_cycles,
        );
        #[cfg(feature = "stdio")]
        let mut machine_builder = DefaultMachineBuilder::new(machine_core)
            .instruction_cycle_func(&instruction_cycles)
            .syscall(Box::new(Stdio::new(false)));
        #[cfg(not(feature = "stdio"))]
        let mut machine_builder = DefaultMachineBuilder::new(machine_core).instruction_cycle_func(&instruction_cycles);
        if let Some(data) = matches_dump_file {
            machine_builder = machine_builder.syscall(Box::new(ElfDumper::new(data.to_string(), 4097, 64)));
        }
        let machine_syscalls = verifier.generate_syscalls(verifier_script_version, verifier_script_group);
        machine_builder =
            machine_syscalls.into_iter().fold(machine_builder, |builder, syscall| builder.syscall(syscall));
        let machine_builder = if let Some(fs) = fs_syscall.clone() {
            machine_builder.syscall(Box::new(fs))
        } else {
            machine_builder
        };
        let machine_builder = machine_builder.syscall(Box::new(TimeNow::new()));
        let machine_builder = machine_builder.syscall(Box::new(Random::new()));
        let machine_builder = machine_builder.syscall(Box::new(FileOperation::new()));
        let machine = machine_builder.build();
        machine
    };

    let machine_step =
        |machine: &mut PProfMachine<DefaultCoreMachine<u64, WXorXMemory<MemoryType>>>| -> Result<i8, ckb_vm::Error> {
            machine.machine.set_running(true);
            let mut decoder =
                build_decoder::<u64>(verifier_script_version.vm_isa(), verifier_script_version.vm_version());
            let mut step_result = Ok(());
            let skip_range = if let (Some(s), Some(e)) = (matches_skip_start, matches_skip_end) {
                let s = u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("parse skip start");
                let e = u64::from_str_radix(e.trim_start_matches("0x"), 16).expect("parse skip end");
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
                    if matches_step > 1 {
                        println!("Machine: {}", machine.machine);
                    }
                }
                step_result = machine.machine.step(&mut decoder);
            }
            if step_result.is_err() {
                Err(step_result.unwrap_err())
            } else {
                Ok(machine.machine.exit_code())
            }
        };

    if matches_mode == "full" {
        let mut machine = PProfMachine::new(machine_init(), Profile::new(&verifier_program)?);
        let bytes = machine.load_program(&verifier_program, &verifier_args_byte)?;
        let transferred_cycles = transferred_byte_cycles(bytes);
        machine.machine.add_cycles(transferred_cycles)?;
        let result = if matches_step > 0 {
            machine_step(&mut machine)
        } else {
            machine.run()
        };
        match result {
            Ok(data) => {
                println!("Run result: {:?}", data);
                println!(
                    "Total cycles consumed: {}",
                    HumanReadableCycles(machine.machine.cycles())
                );
                println!(
                    "Transfer cycles: {}, running cycles: {}",
                    HumanReadableCycles(transferred_cycles),
                    HumanReadableCycles(machine.machine.cycles() - transferred_cycles)
                );
                if let Some(fp) = matches_pprof {
                    let mut output = std::fs::File::create(&fp)?;
                    machine.profile.display_flamegraph(&mut output);
                }
            }
            Err(err) => {
                println!("Trace:");
                machine.profile.display_stacktrace("  ", &mut std::io::stdout());
                println!("Error:");
                println!("  {:?}", err);
            }
        }
        return Ok(());
    }

    if matches_mode == "fast" {
        let mut machine = machine_init();
        let bytes = machine.load_program(&verifier_program, &verifier_args_byte)?;
        let transferred_cycles = transferred_byte_cycles(bytes);
        machine.add_cycles(transferred_cycles)?;
        println!("Run result: {:?}", machine.run());
        println!("Total cycles consumed: {}", HumanReadableCycles(machine.cycles()));
        println!(
            "Transfer cycles: {}, running cycles: {}",
            HumanReadableCycles(transferred_cycles),
            HumanReadableCycles(machine.cycles() - transferred_cycles)
        );
        return Ok(());
    }

    if matches_mode == "gdb" {
        let listen_address = matches_gdb_listen.unwrap();
        let listener = TcpListener::bind(listen_address)?;
        for res in listener.incoming() {
            if let Ok(stream) = res {
                let mut machine = machine_init();
                let bytes = machine.load_program(&verifier_program, &verifier_args_byte)?;
                let transferred_cycles = transferred_byte_cycles(bytes);
                machine.add_cycles(transferred_cycles)?;
                machine.set_running(true);
                let h = GdbHandler::new(machine);
                process_packets_from(stream.try_clone().unwrap(), stream, h);
            }
        }
        return Ok(());
    }

    if matches_mode == "probe" {
        #[cfg(not(feature = "probe"))]
        {
            println!("To use probe mode, feature probes must be enabled!");
            return Ok(());
        }

        #[cfg(feature = "probe")]
        {
            use ckb_vm::{instructions::execute, Register};
            use probe::probe;

            let mut machine = machine_init();
            let bytes = machine.load_program(&verifier_program, &verifier_args_byte)?;
            let transferred_cycles = transferred_byte_cycles(bytes);
            machine.add_cycles(transferred_cycles)?;

            machine.set_running(true);
            let mut decoder =
                build_decoder::<u64>(verifier_script_version.vm_isa(), verifier_script_version.vm_version());

            let mut step_result = Ok(());
            while machine.running() && step_result.is_ok() {
                let pc = machine.pc().to_u64();
                step_result = decoder
                    .decode(machine.memory_mut(), pc)
                    .and_then(|inst| {
                        let cycles = machine.instruction_cycle_func()(inst);
                        machine.add_cycles(cycles).map(|_| inst)
                    })
                    .and_then(|inst| {
                        let regs = machine.registers().as_ptr();
                        let memory = (&mut machine.memory_mut().inner_mut()).as_ptr();
                        probe!(ckb_vm, execute_inst, pc, inst, regs, memory);
                        execute(inst, &mut machine)
                    });
            }
            let result = step_result.map(|_| machine.exit_code());

            println!("Run result: {:?}", result);
            println!("Total cycles consumed: {}", HumanReadableCycles(machine.cycles()));
            println!(
                "Transfer cycles: {}, running cycles: {}",
                HumanReadableCycles(transferred_cycles),
                HumanReadableCycles(machine.cycles() - transferred_cycles)
            );
        }
    }

    Ok(())
}
