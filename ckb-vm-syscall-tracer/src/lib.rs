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
use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_mock_tx_types::{MockTransaction, Resource};
use ckb_script::{
    generate_ckb_syscalls,
    types::{DebugPrinter, ScriptGroup, SgData, VmContext, VmId, VmState},
    Scheduler, ROOT_VM_ID,
};
use ckb_script::{
    types::{DataPieceId, Machine},
    TransactionScriptsVerifier, TxVerifyEnv,
};
use ckb_traits::{CellDataProvider, ExtensionProvider, HeaderProvider};
use ckb_types::{
    core::{cell::resolve_transaction, hardfork, EpochNumberWithFraction, HeaderView},
    packed::Byte32,
    prelude::*,
};
use ckb_vm::{
    registers::{A0, A1, A2, A3, A4, A7},
    snapshot2::DataSource,
    CoreMachine, DefaultMachineRunner, Error, Memory, Register, SupportMachine, Syscalls,
};
use clap::{Args, ValueEnum};
use int_enum::IntEnum;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum CollectorKind {
    /// Syscall based collector, data from each syscall are collected for replays.
    Syscall,

    /// Tx based collector, certain data are collected from the tx as a whole
    TxParts,
}

impl TryFrom<&[u8]> for traces::Parts {
    type Error = Error;

    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(v).map_err(|e| Error::External(format!("prost decoding error: {}", e)))
    }
}

impl From<traces::Parts> for Vec<u8> {
    fn from(value: traces::Parts) -> Self {
        value.encode_to_vec()
    }
}

impl TryFrom<&[u8]> for traces::Syscalls {
    type Error = Error;

    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Self::decode(v).map_err(|e| Error::External(format!("prost decoding error: {}", e)))
    }
}

impl From<traces::Syscalls> for Vec<u8> {
    fn from(value: traces::Syscalls) -> Self {
        value.encode_to_vec()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Args)]
pub struct BinaryLocator {
    /// Index of requested cell or witness
    #[arg(long)]
    pub index: u64,

    /// Source of requested cell or witness
    #[arg(long)]
    pub source: u64,

    /// Starting offset of binary in cell or witnes
    #[arg(long)]
    pub offset: u32,

    /// Length of binary
    #[arg(long)]
    pub length: u32,

    /// True to load from a cell, false to load from a witness
    #[arg(long, value_parser = parse_from_cell, default_value_t = true)]
    pub from_cell: bool,
}

fn parse_from_cell(s: &str) -> Result<bool, String> {
    if s == "t" || s == "true" {
        Ok(true)
    } else {
        Ok(false)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CollectorKey {
    pub vm_id: VmId,
    pub generation_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CollectorResult<T> {
    Success { cycles: u64, traces: HashMap<CollectorKey, T> },
    Failure { exit_code: i8 },
}

pub trait Collector: Clone + Default {
    type Trace;

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

    fn seal(self) -> HashMap<CollectorKey, Self::Trace>;

    fn build_verifier<T: Into<MockTransaction>>(
        &self,
        tx: T,
    ) -> Result<TransactionScriptsVerifier<Resource, Self, Machine>, Error> {
        let mock_tx = tx.into();

        let resource = Resource::from_mock_tx(&mock_tx).map_err(Error::External)?;
        let resolved_transaction =
            resolve_transaction(mock_tx.core_transaction(), &mut HashSet::new(), &resource, &resource)
                .map_err(|e| Error::External(format!("resolving transaction error: {}", e)))?;

        let hardforks = hardfork::HardForks {
            ckb2021: hardfork::CKB2021::new_mirana().as_builder().rfc_0032(20).build().unwrap(),
            ckb2023: hardfork::CKB2023::new_mirana().as_builder().rfc_0049(30).build().unwrap(),
        };
        let consensus = Arc::new(ConsensusBuilder::default().hardfork_switch(hardforks).build());
        let epoch = EpochNumberWithFraction::new(35, 0, 1);
        let header_view = HeaderView::new_advanced_builder().epoch(epoch.pack()).build();
        let tx_env = Arc::new(TxVerifyEnv::new_commit(&header_view));
        Ok(TransactionScriptsVerifier::new_with_generator(
            Arc::new(resolved_transaction),
            resource,
            consensus,
            tx_env,
            Self::syscall_generator,
            self.clone(),
        ))
    }

    fn collect(
        self,
        verifier: &TransactionScriptsVerifier<Resource, Self, Machine>,
        script_group: &ScriptGroup,
    ) -> Result<CollectorResult<Self::Trace>, Error> {
        let mut scheduler = verifier
            .create_scheduler(script_group)
            .map_err(|e| Error::External(format!("scheduler creation error: {}", e)))?;
        let cycles = loop {
            let iteration_result = scheduler.iterate()?;
            if let Some((exit_code, cycles)) = iteration_result.exit_status {
                if exit_code != 0 {
                    return Ok(CollectorResult::Failure { exit_code });
                }
                break cycles;
            }
            self.postprocess(&mut scheduler)?;
        };

        Ok(CollectorResult::Success { cycles, traces: self.seal() })
    }
}

#[derive(Default, Clone)]
pub struct TxPartsBasedCollector {
    syscall_collector: SyscallBasedCollector,
    data: Arc<Mutex<HashMap<CollectorKey, traces::Parts>>>,
}

impl TxPartsBasedCollector {
    fn fetch<V, F: Fn(&traces::Parts) -> V>(&self, vm_id: VmId, f: F) -> V {
        let key = self.syscall_collector.key(vm_id);
        let mut m = self.data.lock().expect("lock");

        let parts = m.entry(key).or_default();
        f(parts)
    }

    fn modify<F: Fn(&mut traces::Parts)>(&mut self, vm_id: VmId, f: F) {
        let key = self.syscall_collector.key(vm_id);
        let mut m = self.data.lock().expect("lock");

        let parts = m.entry(key).or_default();
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

    fn seal(self) -> HashMap<CollectorKey, Self::Trace> {
        let mut m = self.data.lock().expect("lock").clone();
        for (key, syscalls) in self.syscall_collector.seal() {
            m.entry(key).or_default().other_syscalls = syscalls.syscalls;
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
                    self.data.modify(self.vm_id, |parts| {
                        parts.tx_hash = tx_hash.as_slice().to_vec();
                    });
                    skip_syscall_based_collector = true;
                }
                SyscallCode::LoadCell => {
                    let index = machine.registers()[A3].to_u64();
                    let source = machine.registers()[A4].to_u64();

                    if let Some(actual_index) = locate_input(index, source, &self.sg_data.sg_info.script_group) {
                        let fill_length = std::cmp::min(actual_index + 1, self.sg_data.rtx.resolved_inputs.len());
                        let already_filled_length = self.data.fetch(self.vm_id, |parts| parts.input_cells.len());

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

                            self.data.modify(self.vm_id, |parts| parts.input_cells.extend_from_slice(&inputs));
                        }
                        skip_syscall_based_collector = true;
                    }
                }
                SyscallCode::LoadCellData => {
                    let index = machine.registers()[A3].to_u64();
                    let source = machine.registers()[A4].to_u64();

                    if let Some(actual_index) = locate_input(index, source, &self.sg_data.sg_info.script_group) {
                        let fill_length = std::cmp::min(actual_index + 1, self.sg_data.rtx.resolved_inputs.len());
                        let already_filled_length = self.data.fetch(self.vm_id, |parts| parts.input_cell_data.len());

                        if already_filled_length < fill_length {
                            let input_data: Vec<Vec<u8>> = self
                                .sg_data
                                .rtx
                                .resolved_inputs
                                .iter()
                                .skip(already_filled_length)
                                .take(fill_length - already_filled_length)
                                .map(|meta| {
                                    self.sg_data.data_loader().load_cell_data(meta).expect("load data").to_vec()
                                })
                                .collect();

                            self.data.modify(self.vm_id, |parts| parts.input_cell_data.extend_from_slice(&input_data));
                        }
                        skip_syscall_based_collector = true;
                    }
                }
                SyscallCode::LoadWitness => {
                    let index = machine.registers()[A3].to_u64();
                    let source = machine.registers()[A4].to_u64();

                    if let Some(actual_index) = locate_witness(index, source, &self.sg_data.sg_info.script_group) {
                        let fill_length =
                            std::cmp::min(actual_index + 1, self.sg_data.rtx.transaction.witnesses().len());
                        let already_filled_length = self.data.fetch(self.vm_id, |parts| parts.witnesses.len());

                        if already_filled_length < fill_length {
                            let witnesses: Vec<Vec<u8>> = self
                                .sg_data
                                .rtx
                                .transaction
                                .witnesses()
                                .into_iter()
                                .skip(already_filled_length)
                                .take(fill_length - already_filled_length)
                                .map(|witness| witness.raw_data().to_vec())
                                .collect();

                            self.data.modify(self.vm_id, |parts| parts.witnesses.extend_from_slice(&witnesses));
                        }
                        skip_syscall_based_collector = true;
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
    partial_contents: Arc<Mutex<HashMap<CollectorKey, PartialSyscallContent>>>,
    data: Arc<Mutex<HashMap<CollectorKey, traces::Syscalls>>>,
    generation_tracker: GenerationTracker,
}

impl SyscallBasedCollector {
    fn fulfill(&self, key: CollectorKey, syscall: traces::Syscall) {
        self.partial_contents.lock().expect("lock").remove(&key);
        self.data.lock().expect("lock").entry(key.clone()).or_default().syscalls.push(syscall);
    }

    pub fn key(&self, vm_id: VmId) -> CollectorKey {
        self.generation_tracker.key(vm_id)
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
        // Generation tracker only tracks, never processes syscalls. So
        // it's safe to concatenate both vectors.
        let mut syscalls = GenerationTracker::syscall_generator(vm_id, sg_data, vm_context, &data.generation_tracker);
        for syscall in generate_ckb_syscalls(vm_id, sg_data, vm_context, &debug_printer()) {
            syscalls.push(syscall);
        }

        vec![Box::new(SyscallBasedCollectorVMSyscalls { vm_id: *vm_id, data: data.clone(), syscalls })]
    }

    fn postprocess<DL, V, M>(&self, scheduler: &mut Scheduler<DL, V, M>) -> Result<(), Error>
    where
        DL: CellDataProvider + HeaderProvider + ExtensionProvider + Send + Sync + Clone,
        V: Clone,
        M: DefaultMachineRunner,
    {
        self.generation_tracker.postprocess(scheduler)?;

        let mut fulfills = vec![];
        for (key, partial_content) in self.partial_contents.lock().expect("lock").iter() {
            // For runnable VMs, apply the partial content for syscall traces
            if scheduler.state(&key.vm_id) == Some(VmState::Runnable) {
                let syscall = scheduler.peek(
                    &key.vm_id,
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
                fulfills.push((key.clone(), syscall));
            }
        }
        for (key, syscall) in fulfills {
            self.fulfill(key, syscall);
        }
        Ok(())
    }

    fn seal(self) -> HashMap<CollectorKey, Self::Trace> {
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
        let key = self.data.key(self.vm_id);
        assert!(!self.data.partial_contents.lock().expect("lock").contains_key(&key));

        let partial_content = build_partial_content(machine)?;

        let result = delegate_to_syscalls(machine, &mut self.syscalls);
        if let Some(partial_content) = partial_content {
            match result {
                Ok(true) => {
                    // Syscall is completed, we can apply partial content now
                    let data = apply_partial_content(&partial_content, &mut ReadonlyMachine::new(machine))?;
                    self.data.fulfill(key, data.clone());
                }
                Err(Error::Yield) => {
                    // Wait till the VM becomes runnable again to apply partial content
                    self.data.partial_contents.lock().expect("lock").insert(key, partial_content);
                }
                _ => {
                    // The syscall is not handled, or unrecoverable errors happen,
                    // we don't do anything here.
                }
            }
        }

        result
    }
}

enum PartialSyscallContent {
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
            SyscallCode::Debug => return Ok(None),
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
            let process_id = extract_spawned_process_id(machine)?;
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

#[derive(Default, Clone)]
pub struct GenerationTracker {
    pending: Arc<Mutex<HashSet<VmId>>>,
    generations: Arc<Mutex<HashMap<VmId, u64>>>,
}

impl GenerationTracker {
    fn mark_pending(&self, vm_id: VmId) {
        let mut s = self.pending.lock().expect("lock");

        s.insert(vm_id);
    }

    fn increase_generation(&self, vm_id: VmId) {
        let mut m = self.generations.lock().expect("lock");

        *m.entry(vm_id).or_default() += 1;
    }

    pub fn generation(&self, vm_id: VmId) -> u64 {
        let mut m = self.generations.lock().expect("lock");

        *m.entry(vm_id).or_default()
    }

    pub fn key(&self, vm_id: VmId) -> CollectorKey {
        CollectorKey { vm_id, generation_id: self.generation(vm_id) }
    }
}

impl Collector for GenerationTracker {
    type Trace = ();

    fn syscall_generator<DL, M>(
        vm_id: &VmId,
        _sg_data: &SgData<DL>,
        _vm_context: &VmContext<DL>,
        data: &Self,
    ) -> Vec<Box<(dyn Syscalls<M>)>>
    where
        DL: CellDataProvider + HeaderProvider + ExtensionProvider + Send + Sync + Clone + 'static,
        M: SupportMachine + 'static,
    {
        vec![Box::new(GenerationTrackerSyscalls { vm_id: *vm_id, data: data.clone() })]
    }

    fn postprocess<DL, V, M>(&self, scheduler: &mut Scheduler<DL, V, M>) -> Result<(), Error>
    where
        DL: CellDataProvider + HeaderProvider + ExtensionProvider + Send + Sync + Clone,
        V: Clone,
        M: DefaultMachineRunner,
    {
        for vm_id in self.pending.lock().expect("lock").drain() {
            assert_eq!(scheduler.state(&vm_id), Some(VmState::Runnable));
            let terminated = scheduler.peek(
                &vm_id,
                |machine| {
                    let machine = ReadonlyMachine::new(machine.inner_mut());
                    Ok(machine.registers()[A0].to_u64() == 0)
                },
                |snapshot, sg_data| {
                    let machine =
                        ReadonlySnapshotMachine::<_, _, <<M as DefaultMachineRunner>::Inner as CoreMachine>::REG>::new(
                            snapshot, sg_data,
                        );
                    Ok(machine.registers()[A0].to_u64() == 0)
                },
            )?;
            if terminated {
                self.increase_generation(vm_id);
            }
        }
        Ok(())
    }

    fn seal(self) -> HashMap<CollectorKey, ()> {
        HashMap::default()
    }
}

struct GenerationTrackerSyscalls {
    vm_id: VmId,
    data: GenerationTracker,
}

impl<M: SupportMachine> Syscalls<M> for GenerationTrackerSyscalls {
    fn initialize(&mut self, _machine: &mut M) -> Result<(), Error> {
        Ok(())
    }

    fn ecall(&mut self, machine: &mut M) -> Result<bool, Error> {
        if let Ok(code) = SyscallCode::try_from(machine.registers()[A7].to_u64()) {
            if code == SyscallCode::Exec {
                self.data.mark_pending(self.vm_id);
            }
        }
        Ok(false)
    }
}

#[derive(Default, Clone)]
pub struct BinaryLocatorCollector<C: Collector> {
    partial_locators: Arc<Mutex<HashMap<CollectorKey, PartialLocator>>>,
    data: Arc<Mutex<HashMap<CollectorKey, BinaryLocator>>>,
    generation_tracker: GenerationTracker,
    collector: C,
}

impl<C: Collector + Send + 'static> Collector for BinaryLocatorCollector<C> {
    type Trace = (BinaryLocator, C::Trace);

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
        // Generation tracker only tracks, never processes syscalls. So
        // it's safe to concatenate both vectors.
        let mut syscalls = GenerationTracker::syscall_generator(vm_id, sg_data, vm_context, &data.generation_tracker);
        for syscall in C::syscall_generator(vm_id, sg_data, vm_context, &data.collector) {
            syscalls.push(syscall);
        }

        vec![Box::new(BinaryLocatorCollectorSyscalls { vm_id: *vm_id, data: data.clone(), syscalls })]
    }

    fn postprocess<DL, V, M>(&self, scheduler: &mut Scheduler<DL, V, M>) -> Result<(), Error>
    where
        DL: CellDataProvider + HeaderProvider + ExtensionProvider + Send + Sync + Clone,
        V: Clone,
        M: DefaultMachineRunner,
    {
        self.generation_tracker.postprocess(scheduler)?;
        self.collector.postprocess(scheduler)?;

        let sg_data = scheduler.sg_data().clone();

        for (key, partial_locator) in self.partial_locators.lock().expect("lock").drain() {
            assert_eq!(scheduler.state(&key.vm_id), Some(VmState::Runnable));

            let new_key = self.generation_tracker.key(key.vm_id);
            let locator = scheduler.peek(
                &key.vm_id,
                |machine| {
                    apply_partial_locator(
                        &key,
                        &new_key,
                        &partial_locator,
                        &mut ReadonlyMachine::new(machine.inner_mut()),
                        &sg_data,
                    )
                },
                |snapshot, sg_data| {
                    apply_partial_locator(
                            &key,
                            &new_key,
                            &partial_locator,
                            &mut ReadonlySnapshotMachine::<
                                _,
                                _,
                                <<M as DefaultMachineRunner>::Inner as CoreMachine>::REG,
                            >::new(snapshot, sg_data),
                            sg_data,
                        )
                },
            )?;

            if let Some((vm_id, locator)) = locator {
                let key = self.generation_tracker.key(vm_id);
                self.data.lock().expect("lock").insert(key, locator);
            }
        }
        Ok(())
    }

    fn seal(self) -> HashMap<CollectorKey, Self::Trace> {
        let mut self_data = self.data.lock().expect("lock").clone();

        let mut result = HashMap::default();
        for (key, collector_trace) in self.collector.seal().drain() {
            if let Some(self_trace) = self_data.remove(&key) {
                result.insert(key, (self_trace, collector_trace));
            }
        }
        result
    }

    // BinaryLocatorCollector overrides collect method to mark locator for root script.
    fn collect(
        self,
        verifier: &TransactionScriptsVerifier<Resource, Self, Machine>,
        script_group: &ScriptGroup,
    ) -> Result<CollectorResult<Self::Trace>, Error> {
        let mut scheduler = verifier
            .create_scheduler(script_group)
            .map_err(|e| Error::External(format!("scheduler creation error: {}", e)))?;

        let root_locator = BinaryLocator {
            index: scheduler
                .sg_data()
                .tx_info
                .extract_referenced_dep_index(&script_group.script)
                .map_err(|e| Error::External(format!("extract dep index: {}", e)))? as u64,
            source: Source::CellDep as u64,
            offset: 0,
            length: verifier
                .extract_script(&script_group.script)
                .map_err(|e| Error::External(format!("extract script error: {}", e)))?
                .len() as u32,
            from_cell: true,
        };
        self.data.lock().expect("lock").insert(CollectorKey { vm_id: ROOT_VM_ID, generation_id: 0 }, root_locator);

        let cycles = loop {
            let iteration_result = scheduler.iterate()?;
            if let Some((exit_code, cycles)) = iteration_result.exit_status {
                if exit_code != 0 {
                    return Ok(CollectorResult::Failure { exit_code });
                }
                break cycles;
            }
            self.postprocess(&mut scheduler)?;
        };

        Ok(CollectorResult::Success { cycles, traces: self.seal() })
    }
}

struct BinaryLocatorCollectorSyscalls<C: Collector, M> {
    vm_id: VmId,
    data: BinaryLocatorCollector<C>,
    syscalls: Vec<Box<(dyn Syscalls<M>)>>,
}

impl<C: Collector + Send, M: SupportMachine> Syscalls<M> for BinaryLocatorCollectorSyscalls<C, M> {
    fn initialize(&mut self, machine: &mut M) -> Result<(), Error> {
        for syscall in &mut self.syscalls {
            syscall.initialize(machine)?;
        }
        Ok(())
    }

    fn ecall(&mut self, machine: &mut M) -> Result<bool, Error> {
        let key = self.data.generation_tracker.key(self.vm_id);
        assert!(!self.data.partial_locators.lock().expect("lock").contains_key(&key));

        if let Ok(code) = SyscallCode::try_from(machine.registers()[A7].to_u64()) {
            if code == SyscallCode::Exec || code == SyscallCode::Spawn {
                // Tracer requires spawn syscalls, when spawn is enabled,
                // exec will use V2 implementation, which uses a yield
                // in syscalls. So we don't have to check the result of
                // delegate_to_syscalls
                if let Some(partial_locator) = build_partial_locator(machine) {
                    self.data.partial_locators.lock().expect("lock").insert(key, partial_locator);
                }
            }
        }

        delegate_to_syscalls(machine, &mut self.syscalls)
    }
}

enum PartialLocator {
    Exec(BinaryLocator),
    Spawn(BinaryLocator),
}

fn build_partial_locator<M: SupportMachine>(machine: &mut M) -> Option<PartialLocator> {
    let regs = machine.registers();
    let index = regs[A0].to_u64();
    let source = regs[A1].to_u64();
    let bounds = regs[A3].to_u64();
    let offset = (bounds >> 32) as u32;
    let length = bounds as u32;
    let from_cell = regs[A2].to_u64() == 0;
    let locator = BinaryLocator { index, source, offset, length, from_cell };

    if let Ok(code) = machine.registers()[A7].to_u64().try_into() {
        match code {
            SyscallCode::Exec => Some(PartialLocator::Exec(locator)),
            SyscallCode::Spawn => Some(PartialLocator::Spawn(locator)),
            _ => None,
        }
    } else {
        None
    }
}

fn apply_partial_locator<M: SupportMachine, DL: CellDataProvider>(
    old_key: &CollectorKey,
    new_key: &CollectorKey,
    partial_locator: &PartialLocator,
    machine: &mut M,
    sg_data: &SgData<DL>,
) -> Result<Option<(VmId, BinaryLocator)>, Error> {
    assert_eq!(old_key.vm_id, new_key.vm_id);

    match partial_locator {
        PartialLocator::Exec(locator) => {
            if old_key != new_key {
                Ok(Some((new_key.vm_id, normalize_locator(locator, sg_data)?)))
            } else {
                Ok(None)
            }
        }
        PartialLocator::Spawn(locator) => {
            let process_id = extract_spawned_process_id(machine)?;
            assert_ne!(process_id, new_key.vm_id);

            Ok(Some((process_id, normalize_locator(locator, sg_data)?)))
        }
    }
}

// Normalize a BinaryLocator so length does not contain 0. While CKB does not
// need this, it aids debugging purposes.
fn normalize_locator<DL: CellDataProvider>(
    locator: &BinaryLocator,
    sg_data: &SgData<DL>,
) -> Result<BinaryLocator, Error> {
    if locator.length > 0 {
        return Ok(locator.clone());
    }

    let data_piece_id = DataPieceId::try_from((locator.source, locator.index, if locator.from_cell { 0 } else { 1 }))
        .map_err(|e| Error::External(format!("Converting data piece error: {}", e)))?;

    let (_, length) = sg_data
        .load_data(&data_piece_id, locator.offset as u64, 0)
        .ok_or_else(|| Error::External(format!("Locator {:?} is invalid!", locator)))?;

    let mut locator = locator.clone();
    locator.length = length as u32;

    Ok(locator)
}

#[repr(u64)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, IntEnum)]
pub enum SyscallCode {
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
pub enum Source {
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
        if !message.is_empty() {
            println!("Script log: {}", message);
        }
    })
}

fn locate_input(index: u64, source: u64, script_group: &ScriptGroup) -> Option<usize> {
    if source == Source::Input as u64 {
        return Some(index as usize);
    } else if source == Source::GroupInput as u64 {
        return script_group.input_indices.get(index as usize).copied();
    }
    None
}

fn locate_witness(index: u64, source: u64, script_group: &ScriptGroup) -> Option<usize> {
    if source == Source::Input as u64 || source == Source::Output as u64 {
        return Some(index as usize);
    } else if source == Source::GroupInput as u64 {
        return script_group.input_indices.get(index as usize).copied();
    } else if source == Source::GroupOutput as u64 {
        return script_group.output_indices.get(index as usize).copied();
    }
    None
}

fn extract_spawned_process_id<M: SupportMachine>(machine: &mut M) -> Result<u64, Error> {
    let spgs_addr = machine.registers()[A4].clone();
    let process_id_addr_addr = spgs_addr.overflowing_add(&M::REG::from_u64(16));
    let process_id_addr = machine.memory_mut().load64(&process_id_addr_addr)?;
    let process_id = machine.memory_mut().load64(&process_id_addr)?.to_u64();

    Ok(process_id)
}
