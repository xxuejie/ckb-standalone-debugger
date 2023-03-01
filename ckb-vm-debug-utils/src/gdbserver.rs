use byteorder::{ByteOrder, LittleEndian};
use ckb_vm::{
    decoder::build_decoder, CoreMachine, DefaultCoreMachine, DefaultMachine, Error as CkbError, Memory, SupportMachine,
    RISCV_GENERAL_REGISTER_NUMBER,
};

use gdb_remote_protocol::{
    Breakpoint, Error, Handler, MemoryRegion, ProcessType, StopReason, ThreadId, VCont, VContFeature, Watchpoint,
};
use log::debug;
use std::borrow::Cow;
use std::cell::RefCell;

fn show_warning(e: &CkbError) {
    println!(
        "Fatal error in ckb-vm occurred: {:?}. Press Ctrl+C to quit or use gdb to attach it.",
        e
    );
    println!("Note: it doesn't mean any coding error in ckb-vm.");
    println!("This session can't be re-used. It is paused for post-mortem.")
}

fn format_register_value(v: u64) -> Vec<u8> {
    let mut buf = [0u8; 8];
    LittleEndian::write_u64(&mut buf, v);
    buf.to_vec()
}

pub struct WatchPointStatus {
    pub watchpoint: Watchpoint,
    pub data: Vec<u8>,
    pub has_data: bool,
}

impl WatchPointStatus {
    fn new(wp: Watchpoint) -> Self {
        let mut data = Vec::<u8>::new();
        data.resize(wp.n_bytes as usize, 0);
        WatchPointStatus {
            watchpoint: wp,
            data,
            has_data: false,
        }
    }
    fn has_change<H: Handler>(&mut self, handler: &H) -> Result<bool, Error> {
        let has_data = self.has_data;

        let mem = MemoryRegion {
            address: self.watchpoint.addr,
            length: self.watchpoint.n_bytes,
        };
        let new_content = handler.read_memory(mem)?;
        let result = if new_content == self.data {
            Ok(false)
        } else {
            self.data = new_content;
            Ok(true)
        };
        self.has_data = true;

        if has_data {
            result
        } else {
            Ok(false)
        }
    }
}

pub struct GdbHandler<'a, M: Memory<REG = u64> + Default> {
    machine: RefCell<DefaultMachine<'a, DefaultCoreMachine<u64, M>>>,
    breakpoints: RefCell<Vec<Breakpoint>>,
    watchpoints: RefCell<Vec<WatchPointStatus>>,
}

impl<'a, M: Memory<REG = u64> + Default> GdbHandler<'a, M> {
    fn at_breakpoint(&self) -> bool {
        let pc = *self.machine.borrow().pc();
        self.breakpoints.borrow().iter().any(|b| b.addr == pc)
    }
    fn at_watchpoint(&self) -> Result<bool, Error> {
        let mut result = false;
        for wp in self.watchpoints.borrow_mut().iter_mut() {
            if wp.has_change(self)? {
                result = true;
            }
        }
        Ok(result)
    }

    pub fn new(machine: DefaultMachine<'a, DefaultCoreMachine<u64, M>>) -> Self {
        GdbHandler {
            machine: RefCell::new(machine),
            breakpoints: RefCell::new(vec![]),
            watchpoints: RefCell::new(vec![]),
        }
    }
}

impl<'a, M: Memory<REG = u64> + Default> Handler for GdbHandler<'a, M> {
    fn attached(&self, _pid: Option<u64>) -> Result<ProcessType, Error> {
        Ok(ProcessType::Created)
    }

    fn halt_reason(&self) -> Result<StopReason, Error> {
        // SIGINT
        Ok(StopReason::Signal(2))
    }

    fn read_general_registers(&self) -> Result<Vec<u8>, Error> {
        let registers: Vec<Vec<u8>> =
            self.machine.borrow().registers().iter().map(|v| format_register_value(*v)).collect();
        Ok(registers.concat())
    }

    fn read_register(&self, register: u64) -> Result<Vec<u8>, Error> {
        let register = register as usize;
        if register < RISCV_GENERAL_REGISTER_NUMBER {
            Ok(format_register_value(self.machine.borrow().registers()[register]))
        } else if register == RISCV_GENERAL_REGISTER_NUMBER {
            Ok(format_register_value(*self.machine.borrow().pc()))
        } else {
            Err(Error::Error(1))
        }
    }

    fn write_register(&self, register: u64, contents: &[u8]) -> Result<(), Error> {
        let mut buffer = [0u8; 8];
        if contents.len() > 8 {
            error!("Register value too large!");
            return Err(Error::Error(2));
        }
        buffer[0..contents.len()].copy_from_slice(contents);
        let value = LittleEndian::read_u64(&buffer[..]);
        let register = register as usize;
        if register < RISCV_GENERAL_REGISTER_NUMBER {
            self.machine.borrow_mut().set_register(register, value);
            Ok(())
        } else if register == RISCV_GENERAL_REGISTER_NUMBER {
            self.machine.borrow_mut().update_pc(value);
            self.machine.borrow_mut().commit_pc();
            Ok(())
        } else {
            Err(Error::Error(2))
        }
    }

    fn read_memory(&self, region: MemoryRegion) -> Result<Vec<u8>, Error> {
        let mut values = vec![];
        for address in region.address..(region.address + region.length) {
            let value = self.machine.borrow_mut().memory_mut().load8(&address).map_err(|e| {
                error!("Error reading memory address {:x}: {:?}", address, e);
                Error::Error(3)
            })?;
            values.push(value as u8);
        }
        Ok(values)
    }

    fn write_memory(&self, address: u64, bytes: &[u8]) -> Result<(), Error> {
        self.machine.borrow_mut().memory_mut().store_bytes(address, bytes).map_err(|e| {
            error!("Error writing memory address {:x}: {:?}", address, e);
            Error::Error(4)
        })?;
        Ok(())
    }

    fn query_supported_vcont(&self) -> Result<Cow<'static, [VContFeature]>, Error> {
        // Even though we won't support all of vCont features, gdb feature
        // detection only work when we include all of them. The other solution
        // is to use the plain old s or c, but the RSP parser we are using here
        // doesn't support them yet.
        Ok(Cow::from(
            &[
                VContFeature::Continue,
                VContFeature::ContinueWithSignal,
                VContFeature::Step,
                VContFeature::StepWithSignal,
                VContFeature::Stop,
                VContFeature::RangeStep,
            ][..],
        ))
    }

    fn vcont(&self, request: Vec<(VCont, Option<ThreadId>)>) -> Result<StopReason, Error> {
        let mut decoder = build_decoder::<u64>(self.machine.borrow().isa(), self.machine.borrow().version());
        let (vcont, _thread_id) = &request[0];
        match vcont {
            VCont::Continue => {
                let res = self.machine.borrow_mut().step(&mut decoder);
                if res.is_err() {
                    show_warning(&res.err().unwrap());
                    return Ok(StopReason::Signal(5));
                }
                // at_watchpoint can't be in one expression with self.machine.borrow because
                // it will borrow_mut `machine` inside
                while (!self.at_breakpoint()) && self.machine.borrow().running() {
                    if self.at_watchpoint()? {
                        break;
                    }
                    let res = self.machine.borrow_mut().step(&mut decoder);
                    if res.is_err() {
                        show_warning(&res.err().unwrap());
                        return Ok(StopReason::Signal(5));
                    }
                }
            }
            VCont::Step => {
                if self.machine.borrow().running() {
                    let res = self.machine.borrow_mut().step(&mut decoder);
                    if res.is_err() {
                        show_warning(&res.err().unwrap());
                        return Ok(StopReason::Signal(5));
                    }
                }
            }
            VCont::RangeStep(range) => {
                let res = self.machine.borrow_mut().step(&mut decoder);
                if res.is_err() {
                    show_warning(&res.err().unwrap());
                    return Ok(StopReason::Signal(5));
                }
                while self.machine.borrow().pc() >= &range.start
                    && self.machine.borrow().pc() < &range.end
                    && (!self.at_breakpoint())
                    && self.machine.borrow().running()
                {
                    if self.at_watchpoint()? {
                        break;
                    }
                    let res = self.machine.borrow_mut().step(&mut decoder);
                    if res.is_err() {
                        show_warning(&res.err().unwrap());
                        return Ok(StopReason::Signal(5));
                    }
                }
            }
            v => {
                debug!("Unspported vcont type: {:?}", v);
                return Err(Error::Error(5));
            }
        }
        if self.machine.borrow().running() {
            // SIGTRAP
            Ok(StopReason::Signal(5))
        } else {
            Ok(StopReason::Exited(0, self.machine.borrow().exit_code() as u8))
        }
    }

    fn insert_software_breakpoint(&self, breakpoint: Breakpoint) -> Result<(), Error> {
        self.breakpoints.borrow_mut().push(breakpoint);
        Ok(())
    }

    fn remove_software_breakpoint(&self, breakpoint: Breakpoint) -> Result<(), Error> {
        self.breakpoints.borrow_mut().retain(|b| b != &breakpoint);
        Ok(())
    }

    fn insert_write_watchpoint(&self, watchpoint: Watchpoint) -> Result<(), Error> {
        let wp = WatchPointStatus::new(watchpoint);
        self.watchpoints.borrow_mut().push(wp);
        debug!(
            "insert watch point at {:x} with length {}",
            watchpoint.addr, watchpoint.n_bytes
        );
        Ok(())
    }
    fn remove_write_watchpoint(&self, wp: Watchpoint) -> Result<(), Error> {
        self.watchpoints.borrow_mut().retain(|b| b.watchpoint.addr != wp.addr || b.watchpoint.n_bytes != wp.n_bytes);
        debug!("remove watch point at {:x} with length {}", wp.addr, wp.n_bytes);
        Ok(())
    }
}
