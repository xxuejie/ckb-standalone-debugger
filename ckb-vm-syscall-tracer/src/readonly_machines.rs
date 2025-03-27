use ckb_vm::{
    snapshot2::{DataSource, Snapshot2},
    Bytes, CoreMachine, Error, Memory, Register, SupportMachine, RISCV_GENERAL_REGISTER_NUMBER, RISCV_PAGESIZE,
    RISCV_PAGE_SHIFTS,
};

/// ReadonlyMachine wraps on top of an existing SupportMachine, and disables
/// all mutates, providing a readonly interfact to a particular VM. By disabling
/// mutates, we mean that all APIs mutating VM states will panic.
pub struct ReadonlyMachine<'a, M>(&'a mut M);

impl<'a, M> ReadonlyMachine<'a, M> {
    pub fn new(machine: &'a mut M) -> Self {
        Self(machine)
    }
}

impl<'a, M: SupportMachine> Memory for ReadonlyMachine<'a, M> {
    type REG = M::REG;

    fn new() -> Self {
        unreachable!()
    }

    fn new_with_memory(_memory_size: usize) -> Self {
        unreachable!()
    }

    fn init_pages(
        &mut self,
        _addr: u64,
        _size: u64,
        _flags: u8,
        _source: Option<Bytes>,
        _offset_from_addr: u64,
    ) -> Result<(), Error> {
        unreachable!()
    }

    fn fetch_flag(&mut self, _page: u64) -> Result<u8, Error> {
        unreachable!()
    }

    fn set_flag(&mut self, _page: u64, _flag: u8) -> Result<(), Error> {
        unreachable!()
    }

    fn clear_flag(&mut self, _page: u64, _flag: u8) -> Result<(), Error> {
        unreachable!()
    }

    fn memory_size(&self) -> usize {
        unreachable!()
    }

    fn store_byte(&mut self, _addr: u64, _size: u64, _value: u8) -> Result<(), Error> {
        unreachable!()
    }

    fn store_bytes(&mut self, _addr: u64, _value: &[u8]) -> Result<(), Error> {
        unreachable!()
    }

    fn load_bytes(&mut self, addr: u64, size: u64) -> Result<Bytes, Error> {
        self.0.memory_mut().load_bytes(addr, size)
    }

    fn execute_load16(&mut self, _addr: u64) -> Result<u16, Error> {
        unreachable!()
    }

    fn execute_load32(&mut self, _addr: u64) -> Result<u32, Error> {
        unreachable!()
    }

    fn load8(&mut self, addr: &Self::REG) -> Result<Self::REG, Error> {
        self.0.memory_mut().load8(addr)
    }

    fn load16(&mut self, addr: &Self::REG) -> Result<Self::REG, Error> {
        self.0.memory_mut().load16(addr)
    }

    fn load32(&mut self, addr: &Self::REG) -> Result<Self::REG, Error> {
        self.0.memory_mut().load32(addr)
    }

    fn load64(&mut self, addr: &Self::REG) -> Result<Self::REG, Error> {
        self.0.memory_mut().load64(addr)
    }

    fn store8(&mut self, _addr: &Self::REG, _value: &Self::REG) -> Result<(), Error> {
        unreachable!()
    }

    fn store16(&mut self, _addr: &Self::REG, _value: &Self::REG) -> Result<(), Error> {
        unreachable!()
    }

    fn store32(&mut self, _addr: &Self::REG, _value: &Self::REG) -> Result<(), Error> {
        unreachable!()
    }

    fn store64(&mut self, _addr: &Self::REG, _value: &Self::REG) -> Result<(), Error> {
        unreachable!()
    }

    fn lr(&self) -> &Self::REG {
        self.0.memory().lr()
    }

    fn set_lr(&mut self, _value: &Self::REG) {
        unreachable!()
    }
}

impl<'a, M: SupportMachine> CoreMachine for ReadonlyMachine<'a, M> {
    type REG = M::REG;
    type MEM = Self;

    fn pc(&self) -> &Self::REG {
        self.0.pc()
    }

    fn update_pc(&mut self, _pc: Self::REG) {
        unreachable!()
    }

    fn commit_pc(&mut self) {
        unreachable!()
    }

    fn memory(&self) -> &Self::MEM {
        self
    }

    fn memory_mut(&mut self) -> &mut Self::MEM {
        self
    }

    fn registers(&self) -> &[Self::REG] {
        self.0.registers()
    }

    fn set_register(&mut self, _idx: usize, _value: Self::REG) {
        unreachable!()
    }

    fn version(&self) -> u32 {
        self.0.version()
    }

    fn isa(&self) -> u8 {
        unreachable!()
    }
}

impl<'a, M: SupportMachine> SupportMachine for ReadonlyMachine<'a, M> {
    fn new_with_memory(_isa: u8, _version: u32, _max_cycles: u64, _memory_size: usize) -> Self
    where
        Self: Sized,
    {
        unreachable!()
    }

    fn cycles(&self) -> u64 {
        self.0.cycles()
    }

    fn set_cycles(&mut self, _cycles: u64) {
        unreachable!()
    }

    fn max_cycles(&self) -> u64 {
        self.0.max_cycles()
    }

    fn set_max_cycles(&mut self, _cycles: u64) {
        unreachable!()
    }

    fn running(&self) -> bool {
        unreachable!()
    }

    fn set_running(&mut self, _running: bool) {
        unreachable!()
    }

    fn reset(&mut self, _max_cycles: u64) {
        unreachable!()
    }

    fn reset_signal(&mut self) -> bool {
        unreachable!()
    }

    fn code(&self) -> &Bytes {
        unreachable!()
    }
}

/// ReadonlySnapshotMachine works on top of a VM snapshot, providing a readonly
/// interfact to the suspended VM. All mutating APIs will panic.
pub struct ReadonlySnapshotMachine<'a, I: Clone + PartialEq, D, R> {
    snapshot: &'a Snapshot2<I>,
    source: &'a D,
    lr: R,
    pc: R,
    registers: [R; RISCV_GENERAL_REGISTER_NUMBER],
}

impl<'a, I, D, R> ReadonlySnapshotMachine<'a, I, D, R>
where
    I: Clone + PartialEq,
    D: DataSource<I>,
    R: Register,
{
    pub fn new(snapshot: &'a Snapshot2<I>, source: &'a D) -> Self {
        let mut registers: [R; RISCV_GENERAL_REGISTER_NUMBER] = Default::default();
        for i in 0..RISCV_GENERAL_REGISTER_NUMBER {
            registers[i] = R::from_u64(snapshot.registers[i]);
        }

        Self {
            snapshot,
            source,
            lr: R::from_u64(snapshot.load_reservation_address),
            pc: R::from_u64(snapshot.pc),
            registers,
        }
    }

    fn fetch_page(&self, page: u64) -> Result<Bytes, Error> {
        let page_start = page << RISCV_PAGE_SHIFTS;
        for (addr, _, content) in &self.snapshot.dirty_pages {
            let addr_end = addr + content.len() as u64;
            if page_start >= *addr && page_start < addr_end {
                assert!(page_start + RISCV_PAGESIZE as u64 <= addr_end);

                let offset = (page_start - addr) as usize;
                return Ok(content[offset..offset + RISCV_PAGESIZE].to_vec().into());
            }
        }
        for (addr, _, id, source_offset, source_length) in &self.snapshot.pages_from_source {
            let addr_end = addr + source_length;
            if page_start >= *addr && page_start < addr_end {
                assert!(page_start + RISCV_PAGESIZE as u64 <= addr_end);

                let offset = source_offset + (page_start - addr);
                let (data, _) = self.source.load_data(id, offset, RISCV_PAGESIZE as u64).expect("missing data");
                assert_eq!(data.len(), RISCV_PAGESIZE);
                return Ok(data);
            }
        }
        // When the snapshot does not contain such a page, return all zeros
        Ok(vec![0; RISCV_PAGESIZE].into())
    }

    /// Load memory data from snapshot
    pub fn load(&self, mut addr: u64, content: &mut [u8]) -> Result<(), Error> {
        let mut loaded = 0;
        while loaded < content.len() {
            let page = addr >> RISCV_PAGE_SHIFTS;
            let page_start = page << RISCV_PAGE_SHIFTS;

            let data = self.fetch_page(page)?;
            let data_offset = (addr - page_start) as usize;
            let read = std::cmp::min(content.len() - loaded, data.len() - data_offset);

            content[loaded..loaded + read].copy_from_slice(&data[data_offset..data_offset + read]);
            loaded += read;
            addr += read as u64;
        }
        Ok(())
    }
}

impl<'a, I, D, R> Memory for ReadonlySnapshotMachine<'a, I, D, R>
where
    I: Clone + PartialEq,
    D: DataSource<I>,
    R: Register,
{
    type REG = R;

    fn new() -> Self {
        unreachable!()
    }

    fn new_with_memory(_memory_size: usize) -> Self {
        unreachable!()
    }

    fn init_pages(
        &mut self,
        _addr: u64,
        _size: u64,
        _flags: u8,
        _source: Option<Bytes>,
        _offset_from_addr: u64,
    ) -> Result<(), Error> {
        unreachable!()
    }

    fn fetch_flag(&mut self, _page: u64) -> Result<u8, Error> {
        unreachable!()
    }

    fn set_flag(&mut self, _page: u64, _flag: u8) -> Result<(), Error> {
        unreachable!()
    }

    fn clear_flag(&mut self, _page: u64, _flag: u8) -> Result<(), Error> {
        unreachable!()
    }

    fn memory_size(&self) -> usize {
        unreachable!()
    }

    fn store_byte(&mut self, _addr: u64, _size: u64, _value: u8) -> Result<(), Error> {
        unreachable!()
    }

    fn store_bytes(&mut self, _addr: u64, _value: &[u8]) -> Result<(), Error> {
        unreachable!()
    }

    fn load_bytes(&mut self, addr: u64, size: u64) -> Result<Bytes, Error> {
        let mut buffer = vec![0; size as usize];
        self.load(addr, &mut buffer[..])?;
        Ok(buffer.into())
    }

    fn execute_load16(&mut self, _addr: u64) -> Result<u16, Error> {
        unreachable!()
    }

    fn execute_load32(&mut self, _addr: u64) -> Result<u32, Error> {
        unreachable!()
    }

    fn load8(&mut self, addr: &Self::REG) -> Result<Self::REG, Error> {
        let mut buffer = [0u8];
        self.load(addr.to_u64(), &mut buffer[..])?;
        Ok(Self::REG::from_u8(buffer[0]))
    }

    fn load16(&mut self, addr: &Self::REG) -> Result<Self::REG, Error> {
        let mut buffer = [0u8, 0u8];
        self.load(addr.to_u64(), &mut buffer[..])?;
        Ok(Self::REG::from_u16(u16::from_le_bytes(buffer)))
    }

    fn load32(&mut self, addr: &Self::REG) -> Result<Self::REG, Error> {
        let mut buffer = [0u8; 4];
        self.load(addr.to_u64(), &mut buffer[..])?;
        Ok(Self::REG::from_u32(u32::from_le_bytes(buffer)))
    }

    fn load64(&mut self, addr: &Self::REG) -> Result<Self::REG, Error> {
        let mut buffer = [0u8; 8];
        self.load(addr.to_u64(), &mut buffer[..])?;
        Ok(Self::REG::from_u64(u64::from_le_bytes(buffer)))
    }

    fn store8(&mut self, _addr: &Self::REG, _value: &Self::REG) -> Result<(), Error> {
        unreachable!()
    }

    fn store16(&mut self, _addr: &Self::REG, _value: &Self::REG) -> Result<(), Error> {
        unreachable!()
    }

    fn store32(&mut self, _addr: &Self::REG, _value: &Self::REG) -> Result<(), Error> {
        unreachable!()
    }

    fn store64(&mut self, _addr: &Self::REG, _value: &Self::REG) -> Result<(), Error> {
        unreachable!()
    }

    fn lr(&self) -> &Self::REG {
        &self.lr
    }

    fn set_lr(&mut self, _value: &Self::REG) {
        unreachable!()
    }
}

impl<'a, I, D, R> CoreMachine for ReadonlySnapshotMachine<'a, I, D, R>
where
    I: Clone + PartialEq,
    D: DataSource<I>,
    R: Register,
{
    type REG = R;
    type MEM = Self;

    fn pc(&self) -> &Self::REG {
        &self.pc
    }

    fn update_pc(&mut self, _pc: Self::REG) {
        unreachable!()
    }

    fn commit_pc(&mut self) {
        unreachable!()
    }

    fn memory(&self) -> &Self::MEM {
        self
    }

    fn memory_mut(&mut self) -> &mut Self::MEM {
        self
    }

    fn registers(&self) -> &[Self::REG] {
        &self.registers
    }

    fn set_register(&mut self, _idx: usize, _value: Self::REG) {
        unreachable!()
    }

    fn version(&self) -> u32 {
        self.snapshot.version
    }

    fn isa(&self) -> u8 {
        unreachable!()
    }
}

impl<'a, I, D, R> SupportMachine for ReadonlySnapshotMachine<'a, I, D, R>
where
    I: Clone + PartialEq,
    D: DataSource<I>,
    R: Register,
{
    fn new_with_memory(_isa: u8, _version: u32, _max_cycles: u64, _memory_size: usize) -> Self
    where
        Self: Sized,
    {
        unreachable!()
    }

    fn cycles(&self) -> u64 {
        self.snapshot.cycles
    }

    fn set_cycles(&mut self, _cycles: u64) {
        unreachable!()
    }

    fn max_cycles(&self) -> u64 {
        self.snapshot.max_cycles
    }

    fn set_max_cycles(&mut self, _cycles: u64) {
        unreachable!()
    }

    fn running(&self) -> bool {
        unreachable!()
    }

    fn set_running(&mut self, _running: bool) {
        unreachable!()
    }

    fn reset(&mut self, _max_cycles: u64) {
        unreachable!()
    }

    fn reset_signal(&mut self) -> bool {
        unreachable!()
    }

    fn code(&self) -> &Bytes {
        unreachable!()
    }
}
