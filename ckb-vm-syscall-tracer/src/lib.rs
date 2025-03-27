pub mod generated {
    pub mod traces {
        include!(concat!(env!("OUT_DIR"), "/generated.traces.rs"));
    }
}
pub mod readonly_machines;

use crate::{
    generated::traces,
    readonly_machines::{ReadonlyMachine, ReadonlySnapshotMachine},
};
use ckb_script::{
    generate_ckb_syscalls,
    types::{DebugPrinter, ScriptGroup, SgData, VmContext, VmId, VmState},
    Scheduler,
};
use ckb_traits::{CellDataProvider, ExtensionProvider, HeaderProvider};
use ckb_types::{packed::Byte32, prelude::*};
use ckb_vm::{
    registers::{A0, A1, A2, A3, A4, A7},
    CoreMachine, DefaultMachineRunner, Error, Memory, Register, SupportMachine, Syscalls,
};
use int_enum::IntEnum;
use prost::Message;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

impl From<traces::Parts> for Vec<u8> {
    fn from(value: traces::Parts) -> Self {
        value.encode_to_vec()
    }
}

impl From<traces::Syscalls> for Vec<u8> {
    fn from(value: traces::Syscalls) -> Self {
        value.encode_to_vec()
    }
}

pub trait Collector: Clone + Default {
    type Trace: Into<Vec<u8>>;

    fn syscall_generator<DL, M>(
        vm_id: &VmId,
        sg_data: &SgData<DL>,
        vm_context: &VmContext<DL>,
        data: &Self,
    ) -> Vec<Box<(dyn Syscalls<M>)>>
    where
        DL: CellDataProvider + HeaderProvider + ExtensionProvider + Send + Sync + Clone + 'static,
        M: SupportMachine + 'static;

    fn postprocess<DL, V, M>(&self, scheduler: &mut Scheduler<DL, V, M>) -> Result<(), Error>
    where
        DL: CellDataProvider + HeaderProvider + ExtensionProvider + Send + Sync + Clone,
        V: Clone,
        M: DefaultMachineRunner;

    fn seal(self) -> HashMap<VmId, Self::Trace>;
}

#[derive(Default, Clone)]
pub struct TxPartsBasedCollector {
    syscall_collector: SyscallBasedCollector,
    data: Arc<Mutex<HashMap<VmId, traces::Parts>>>,
}

impl TxPartsBasedCollector {
    fn fetch<V, F: Fn(&traces::Parts) -> V>(&self, vm_id: &VmId, f: F) -> V {
        let mut m = self.data.lock().expect("lock");

        if !m.contains_key(vm_id) {
            m.insert(*vm_id, traces::Parts::default());
        }
        let parts = m.get(vm_id).unwrap();

        f(parts)
    }

    fn modify<F: Fn(&mut traces::Parts)>(&mut self, vm_id: &VmId, f: F) {
        let mut m = self.data.lock().expect("lock");

        if !m.contains_key(vm_id) {
            m.insert(*vm_id, traces::Parts::default());
        }
        let parts = m.get_mut(vm_id).unwrap();

        f(parts);
    }
}

impl Collector for TxPartsBasedCollector {
    type Trace = traces::Parts;

    fn syscall_generator<DL, M>(
        vm_id: &VmId,
        sg_data: &SgData<DL>,
        vm_context: &VmContext<DL>,
        data: &Self,
    ) -> Vec<Box<(dyn Syscalls<M>)>>
    where
        DL: CellDataProvider + HeaderProvider + ExtensionProvider + Send + Sync + Clone + 'static,
        M: SupportMachine + 'static,
    {
        vec![Box::new(TxPartsBasedCollectorVMSyscalls {
            vm_id: *vm_id,
            sg_data: sg_data.clone(),
            data: data.clone(),
            inner_collector_syscalls: SyscallBasedCollector::syscall_generator(
                vm_id,
                sg_data,
                vm_context,
                &data.syscall_collector,
            ),
            ckb_syscalls: generate_ckb_syscalls(vm_id, sg_data, vm_context, &debug_printer()),
        })]
    }

    fn postprocess<DL, V, M>(&self, scheduler: &mut Scheduler<DL, V, M>) -> Result<(), Error>
    where
        DL: CellDataProvider + HeaderProvider + ExtensionProvider + Send + Sync + Clone,
        V: Clone,
        M: DefaultMachineRunner,
    {
        // TxPartsBasedCollector requires no postprocess, we only need to invoke postprocess
        // for SyscallBasedCollector
        self.syscall_collector.postprocess(scheduler)
    }

    fn seal(self) -> HashMap<VmId, Self::Trace> {
        let mut m = self.data.lock().expect("lock").clone();
        for (vm_id, syscalls) in self.syscall_collector.seal() {
            if !m.contains_key(&vm_id) {
                m.insert(vm_id, traces::Parts::default());
            }
            m.get_mut(&vm_id).unwrap().other_syscalls = syscalls.syscalls;
        }
        m
    }
}

struct TxPartsBasedCollectorVMSyscalls<DL, M> {
    vm_id: VmId,
    sg_data: SgData<DL>,
    data: TxPartsBasedCollector,
    inner_collector_syscalls: Vec<Box<(dyn Syscalls<M>)>>,
    ckb_syscalls: Vec<Box<(dyn Syscalls<M>)>>,
}

impl<DL: CellDataProvider + Send + Sync, M: SupportMachine> Syscalls<M> for TxPartsBasedCollectorVMSyscalls<DL, M> {
    fn initialize(&mut self, machine: &mut M) -> Result<(), Error> {
        for syscall in &mut self.inner_collector_syscalls {
            syscall.initialize(machine)?;
        }
        for syscall in &mut self.ckb_syscalls {
            syscall.initialize(machine)?;
        }
        Ok(())
    }

    fn ecall(&mut self, machine: &mut M) -> Result<bool, Error> {
        // Detect and keep certain tx parts, for those syscalls,
        // we can skip the IOData in SyscallBasedCollector
        let mut skip_syscall_based_collector = false;
        if let Ok(code) = machine.registers()[A7].to_u64().try_into() {
            match code {
                SyscallCode::LoadTxHash => {
                    let tx_hash = self.sg_data.rtx.transaction.hash();
                    self.data.modify(&self.vm_id, |parts| {
                        parts.tx_hash = tx_hash.as_slice().to_vec();
                    });
                    skip_syscall_based_collector = true;
                }
                SyscallCode::LoadCell => {
                    let index = machine.registers()[A3].to_u64();
                    let source = machine.registers()[A4].to_u64();

                    if let Some(actual_index) = locate_input(index, source, &self.sg_data.sg_info.script_group) {
                        let fill_length = std::cmp::min(actual_index + 1, self.sg_data.rtx.resolved_inputs.len());
                        let already_filled_length = self.data.fetch(&self.vm_id, |parts| parts.input_cells.len());

                        if already_filled_length < fill_length {
                            let inputs: Vec<Vec<u8>> = self
                                .sg_data
                                .rtx
                                .resolved_inputs
                                .iter()
                                .skip(already_filled_length)
                                .take(fill_length - already_filled_length)
                                .map(|meta| meta.cell_output.as_slice().to_vec())
                                .collect();

                            self.data.modify(&self.vm_id, |parts| parts.input_cells.extend_from_slice(&inputs));
                            skip_syscall_based_collector = true;
                        }
                    }
                }
                _ => (),
            }
        }

        if skip_syscall_based_collector {
            delegate_to_syscalls(machine, &mut self.ckb_syscalls)
        } else {
            delegate_to_syscalls(machine, &mut self.inner_collector_syscalls)
        }
    }
}

#[derive(Default, Clone)]
pub struct SyscallBasedCollector {
    partial_contents: Arc<Mutex<HashMap<VmId, PartialSyscallContent>>>,
    data: Arc<Mutex<HashMap<VmId, traces::Syscalls>>>,
}

impl SyscallBasedCollector {
    fn insert(&self, vm_id: VmId, syscall: traces::Syscall) {
        let mut m = self.data.lock().expect("lock");

        if !m.contains_key(&vm_id) {
            m.insert(vm_id, traces::Syscalls { syscalls: Vec::new() });
        }

        m.get_mut(&vm_id).unwrap().syscalls.push(syscall);
    }
}

impl Collector for SyscallBasedCollector {
    type Trace = traces::Syscalls;

    fn syscall_generator<DL, M>(
        vm_id: &VmId,
        sg_data: &SgData<DL>,
        vm_context: &VmContext<DL>,
        data: &Self,
    ) -> Vec<Box<(dyn Syscalls<M>)>>
    where
        DL: CellDataProvider + HeaderProvider + ExtensionProvider + Send + Sync + Clone + 'static,
        M: SupportMachine + 'static,
    {
        vec![Box::new(SyscallBasedCollectorVMSyscalls {
            vm_id: *vm_id,
            data: data.clone(),
            syscalls: generate_ckb_syscalls(vm_id, sg_data, vm_context, &debug_printer()),
        })]
    }

    fn postprocess<DL, V, M>(&self, scheduler: &mut Scheduler<DL, V, M>) -> Result<(), Error>
    where
        DL: CellDataProvider + HeaderProvider + ExtensionProvider + Send + Sync + Clone,
        V: Clone,
        M: DefaultMachineRunner,
    {
        let mut partial_contents_to_remove = vec![];
        for (vm_id, partial_content) in self.partial_contents.lock().expect("lock").iter() {
            // For runnable VMs, apply the partial content for syscall traces
            if scheduler.state(vm_id) == Some(VmState::Runnable) {
                let syscall = scheduler.peek(
                    &vm_id,
                    |machine| apply_partial_content(partial_content, &mut ReadonlyMachine::new(machine.inner_mut())),
                    |snapshot, sg_data| {
                        apply_partial_content(
                            partial_content,
                            &mut ReadonlySnapshotMachine::<
                                _,
                                _,
                                <<M as DefaultMachineRunner>::Inner as CoreMachine>::REG,
                            >::new(snapshot, sg_data),
                        )
                    },
                )?;
                self.insert(*vm_id, syscall);
                partial_contents_to_remove.push(*vm_id);
            }
        }
        {
            let mut m = self.partial_contents.lock().expect("lock");
            for vm_id in partial_contents_to_remove {
                m.remove(&vm_id);
            }
        }
        Ok(())
    }

    fn seal(self) -> HashMap<VmId, Self::Trace> {
        self.data.lock().expect("lock").clone()
    }
}

struct SyscallBasedCollectorVMSyscalls<M> {
    vm_id: VmId,
    data: SyscallBasedCollector,
    syscalls: Vec<Box<(dyn Syscalls<M>)>>,
}

impl<M: SupportMachine> Syscalls<M> for SyscallBasedCollectorVMSyscalls<M> {
    fn initialize(&mut self, machine: &mut M) -> Result<(), Error> {
        for syscall in &mut self.syscalls {
            syscall.initialize(machine)?;
        }
        Ok(())
    }

    fn ecall(&mut self, machine: &mut M) -> Result<bool, Error> {
        let mut c = self.data.partial_contents.lock().expect("lock");
        assert!(!c.contains_key(&self.vm_id));

        if let Some(content) = build_partial_content(machine)? {
            c.insert(self.vm_id, content);
        }

        delegate_to_syscalls(machine, &mut self.syscalls)
    }
}

enum PartialSyscallContent {
    Noop,
    ReturnWithCode,
    IoData { data_addr: u64, input_length: u64 },
    Exec,
    Spawn,
    Wait,
    Pipe { fds_addr: u64 },
    Write,
    Read,
    InheritedFd { buffer_addr: u64 },
}

fn build_partial_content<M: SupportMachine>(machine: &mut M) -> Result<Option<PartialSyscallContent>, Error> {
    Ok(if let Ok(code) = machine.registers()[A7].to_u64().try_into() {
        Some(match code {
            SyscallCode::LoadTransaction
            | SyscallCode::LoadScript
            | SyscallCode::LoadTxHash
            | SyscallCode::LoadScriptHash
            | SyscallCode::LoadCell
            | SyscallCode::LoadHeader
            | SyscallCode::LoadInput
            | SyscallCode::LoadWitness
            | SyscallCode::LoadCellByField
            | SyscallCode::LoadHeaderByField
            | SyscallCode::LoadInputByField
            | SyscallCode::LoadCellData
            | SyscallCode::LoadBlockExtension => {
                let data_addr = machine.registers()[A0].to_u64();
                let length_addr = machine.registers()[A1].to_u64();
                let input_length = machine.memory_mut().load64(&M::REG::from_u64(length_addr))?.to_u64();

                PartialSyscallContent::IoData { data_addr, input_length }
            }
            SyscallCode::LoadCellDataAsCode => {
                panic!("Load cell data as code syscall is not supported!");
            }
            SyscallCode::VmVersion => PartialSyscallContent::ReturnWithCode,
            SyscallCode::CurrentCycles => PartialSyscallContent::ReturnWithCode,
            SyscallCode::Exec => PartialSyscallContent::Exec,
            SyscallCode::Spawn => PartialSyscallContent::Spawn,
            SyscallCode::Wait => PartialSyscallContent::Wait,
            SyscallCode::ProcessId => PartialSyscallContent::ReturnWithCode,
            SyscallCode::Pipe => {
                let fds_addr = machine.registers()[A0].to_u64();
                PartialSyscallContent::Pipe { fds_addr }
            }
            SyscallCode::Write => PartialSyscallContent::Write,
            SyscallCode::Read => PartialSyscallContent::Read,
            SyscallCode::InheritedFd => {
                let buffer_addr = machine.registers()[A0].to_u64();
                PartialSyscallContent::InheritedFd { buffer_addr }
            }
            SyscallCode::Close => PartialSyscallContent::ReturnWithCode,
            SyscallCode::Debug => PartialSyscallContent::Noop,
        })
    } else {
        None
    })
}

// When this is invoked, the passed machine must be in runnable state.
fn apply_partial_content<M: SupportMachine>(
    partial_content: &PartialSyscallContent,
    machine: &mut M,
) -> Result<traces::Syscall, Error> {
    Ok(match partial_content {
        PartialSyscallContent::Noop => traces::Syscall { value: Some(traces::syscall::Value::Noop(traces::Noop {})) },
        PartialSyscallContent::ReturnWithCode => {
            let return_code = machine.registers()[A0].to_i64();
            return return_syscall(return_code);
        }
        PartialSyscallContent::IoData { data_addr, input_length } => {
            let return_code = machine.registers()[A0].to_i64();
            if return_code != 0 {
                return return_syscall(return_code);
            }
            let length_addr = machine.registers()[A1].to_u64();
            let output_length = machine.memory_mut().load64(&M::REG::from_u64(length_addr))?.to_u64();

            let actual_data_length = std::cmp::min(*input_length, output_length);
            let data = machine.memory_mut().load_bytes(*data_addr, actual_data_length)?;

            traces::Syscall {
                value: Some(traces::syscall::Value::IoData(traces::IoData {
                    available_data: data.as_ref().to_vec(),
                    additional_length: output_length - data.len() as u64,
                })),
            }
        }
        PartialSyscallContent::Exec => {
            let return_code = machine.registers()[A0].to_i64();
            if return_code != 0 {
                return return_syscall(return_code);
            }
            traces::Syscall { value: Some(traces::syscall::Value::Terminated(traces::Terminated {})) }
        }
        PartialSyscallContent::Spawn => {
            let return_code = machine.registers()[A0].to_i64();
            if return_code != 0 {
                return return_syscall(return_code);
            }
            let spgs_addr = machine.registers()[A4].clone();
            let process_id_addr_addr = spgs_addr.overflowing_add(&M::REG::from_u64(16));
            let process_id_addr = machine.memory_mut().load64(&process_id_addr_addr)?;
            let process_id = machine.memory_mut().load64(&process_id_addr)?.to_u64();
            traces::Syscall { value: Some(traces::syscall::Value::SuccessOutputData(process_id)) }
        }
        PartialSyscallContent::Wait => {
            let return_code = machine.registers()[A0].to_i64();
            if return_code != 0 {
                return return_syscall(return_code);
            }
            let exit_code_addr = machine.registers()[A1].clone();
            let exit_code = machine.memory_mut().load8(&exit_code_addr)?.to_i64() as u64;
            traces::Syscall { value: Some(traces::syscall::Value::SuccessOutputData(exit_code)) }
        }
        PartialSyscallContent::Pipe { fds_addr } => {
            let return_code = machine.registers()[A0].to_i64();
            if return_code != 0 {
                return return_syscall(return_code);
            }
            let fd1 = machine.memory_mut().load64(&M::REG::from_u64(*fds_addr))?.to_u64();
            let fd2 = machine.memory_mut().load64(&M::REG::from_u64(*fds_addr + 8))?.to_u64();
            traces::Syscall { value: Some(traces::syscall::Value::Fds(traces::Fds { fds: vec![fd1, fd2] })) }
        }
        PartialSyscallContent::Write => {
            let return_code = machine.registers()[A0].to_i64();
            if return_code != 0 {
                return return_syscall(return_code);
            }
            let length_addr = machine.registers()[A2].clone();
            let length = machine.memory_mut().load64(&length_addr)?.to_u64();
            traces::Syscall { value: Some(traces::syscall::Value::SuccessOutputData(length)) }
        }
        PartialSyscallContent::Read => {
            let return_code = machine.registers()[A0].to_i64();
            if return_code != 0 {
                return return_syscall(return_code);
            }
            let data_addr = machine.registers()[A1].to_u64();
            let length_addr = machine.registers()[A2].clone();
            let length = machine.memory_mut().load64(&length_addr)?.to_u64();
            let data = machine.memory_mut().load_bytes(data_addr, length)?;

            traces::Syscall {
                value: Some(traces::syscall::Value::IoData(traces::IoData {
                    available_data: data.as_ref().to_vec(),
                    additional_length: 0,
                })),
            }
        }
        PartialSyscallContent::InheritedFd { buffer_addr } => {
            let count_addr = machine.registers()[A1].clone();
            let count = machine.memory_mut().load64(&count_addr)?.to_u64();

            let addr = *buffer_addr;
            let mut fds = Vec::with_capacity(count as usize);
            for i in 0..count {
                fds.push(machine.memory_mut().load64(&M::REG::from_u64(addr + i * 8))?.to_u64());
            }
            traces::Syscall { value: Some(traces::syscall::Value::Fds(traces::Fds { fds })) }
        }
    })
}

fn return_syscall(code: i64) -> Result<traces::Syscall, Error> {
    Ok(traces::Syscall { value: Some(traces::syscall::Value::ReturnWithCode(code)) })
}

#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, IntEnum)]
enum SyscallCode {
    LoadTransaction = 2051,
    LoadScript = 2052,
    LoadTxHash = 2061,
    LoadScriptHash = 2062,
    LoadCell = 2071,
    LoadHeader = 2072,
    LoadInput = 2073,
    LoadWitness = 2074,
    LoadCellByField = 2081,
    LoadHeaderByField = 2082,
    LoadInputByField = 2083,
    LoadCellDataAsCode = 2091,
    LoadCellData = 2092,
    LoadBlockExtension = 2104,
    VmVersion = 2041,
    CurrentCycles = 2042,
    Exec = 2043,
    Spawn = 2601,
    Wait = 2602,
    ProcessId = 2603,
    Pipe = 2604,
    Write = 2605,
    Read = 2606,
    InheritedFd = 2607,
    Close = 2608,
    Debug = 2177,
}

#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, IntEnum)]
enum Source {
    Input = 1,
    Output = 2,
    CellDep = 3,
    HeaderDep = 4,
    GroupInput = 0x0100000000000001,
    GroupOutput = 0x0100000000000002,
}

fn delegate_to_syscalls<M: SupportMachine>(
    machine: &mut M,
    syscalls: &mut [Box<(dyn Syscalls<M>)>],
) -> Result<bool, Error> {
    for syscall in syscalls {
        let processed = syscall.ecall(machine)?;
        if processed {
            return Ok(true);
        }
    }
    Ok(false)
}

fn debug_printer() -> DebugPrinter {
    Arc::new(|_hash: &Byte32, message: &str| {
        let message = message.trim_end_matches('\n');
        if message != "" {
            println!("Script log: {}", message);
        }
    })
}

fn locate_input(index: u64, source: u64, script_group: &ScriptGroup) -> Option<usize> {
    if source == 1 {
        return Some(index as usize);
    } else if source == Source::GroupInput as u64 {
        return script_group.input_indices.get(index as usize).copied();
    }
    None
}
