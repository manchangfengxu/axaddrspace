use core::fmt;
use page_table_entry::{GenericPTE, MappingFlags};
use page_table_multiarch::{PageTable64, PagingMetaData};
use crate::{GuestPhysAddr, HostPhysAddr};

bitflags::bitflags! {
    /// Memory attribute fields in the LoongArch64 translation table format descriptors.
    #[derive(Debug)]
    pub struct LoongArchStage2PTEAttr: usize {
        const V = 1 << 0;        // Valid
        const D = 1 << 1;        // Dirty
        
        // 特权级定义
        const PLV = 0b11 << 2;   // Privilege Level Range
        const PLV0 = 0b00 << 2;  // PLV0
        const PLV1 = 0b01 << 2;  // PLV1
        const PLV2 = 0b10 << 2;  // PLV2
        const PLV3 = 0b11 << 2;  // PLV3
        
        // 内存访问类型
        const MAT = 0b11 << 4;   // Memory Access Type Range
        const MAT_SUC = 0b00 << 4; // Strongly-ordered UnCached
        const MAT_CC = 0b01 << 4;  // Coherent Cached
        const MAT_WUC = 0b10 << 4;  // Weakly-ordered UnCached
        
        const G = 1 << 6;        // Global
        const P = 1 << 7;        // Present
        const W = 1 << 8;        // Writable
        const NR = 1 << 61;      // Not Readable
        const NX = 1 << 62;      // Not Executable
        const RPLV = 1 << 63;    // Relative Privilege Level Check
    }
}

#[repr(usize)]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum LoongArchMemType {
    StronglyUncached = 0,  
    CoherentCached = 1,   
    WeaklyUncached = 2,    
    Reserved = 3,      
}

impl LoongArchStage2PTEAttr {
    const MAT_MASK: usize = 0b11 << 4;
    
    fn mem_type(&self) -> LoongArchMemType {
        let mat = (self.bits() & Self::MAT_MASK) >> 4;
        match mat {
            0 => LoongArchMemType::StronglyUncached,
            1 => LoongArchMemType::CoherentCached,
            2 => LoongArchMemType::WeaklyUncached,
            _ => panic!("Invalid memory access type"),
        }
    }
}

// LoongArch64 Stage2 Page Table Entry
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct LoongArchStage2PTE(usize);

impl LoongArchStage2PTE {
    const PHYS_ADDR_MASK: usize = 0x0000_ffff_ffff_f000; // bits 12..48
    
    pub const fn empty() -> Self {
        Self(0)
    }
}

impl GenericPTE for LoongArchStage2PTE {
    fn bits(self) -> usize {
        self.0
    }
    
    fn new_page(paddr: HostPhysAddr, flags: MappingFlags, is_huge: bool) -> Self {
        let mut attr = LoongArchStage2PTEAttr::from(flags);
        
        attr |= LoongArchStage2PTEAttr::V | LoongArchStage2PTEAttr::D; // Valid + Dirty
        
        if !is_huge {
            attr |= LoongArchStage2PTEAttr::P;
        }
        
        Self(attr.bits() | (paddr.as_usize() & Self::PHYS_ADDR_MASK))
    }
    
    fn new_table(paddr: HostPhysAddr) -> Self {
        let attr = LoongArchStage2PTEAttr::V | LoongArchStage2PTEAttr::P;
        Self(attr.bits() | (paddr.as_usize() & Self::PHYS_ADDR_MASK))
    }
    
    fn paddr(&self) -> HostPhysAddr {
        HostPhysAddr::from(self.0 & Self::PHYS_ADDR_MASK)
    }
    
    fn flags(&self) -> MappingFlags {
        LoongArchStage2PTEAttr::from_bits_truncate(self.0).into()
    }
    
    fn set_paddr(&mut self, paddr: HostPhysAddr) {
        self.0 = (self.0 & !Self::PHYS_ADDR_MASK) | (paddr.as_usize() & Self::PHYS_ADDR_MASK)
    }
    
    fn set_flags(&mut self, flags: MappingFlags, is_huge: bool) {
        let mut attr = LoongArchStage2PTEAttr::from(flags);
        attr |= LoongArchStage2PTEAttr::V | LoongArchStage2PTEAttr::D;
        
        if !is_huge {
            attr |= LoongArchStage2PTEAttr::P;
        }
        
        self.0 = (self.0 & Self::PHYS_ADDR_MASK) | attr.bits();
    }
    
    fn is_unused(&self) -> bool {
        self.0 == 0
    }
    
    fn is_present(&self) -> bool {
        LoongArchStage2PTEAttr::from_bits_truncate(self.0).contains(LoongArchStage2PTEAttr::P)
    }
    
    fn is_huge(&self) -> bool {
        false
    }
    
    fn clear(&mut self) {
        self.0 = 0
    }
}

// Attribute conversion implementation
impl From<LoongArchStage2PTEAttr> for MappingFlags {
    fn from(attr: LoongArchStage2PTEAttr) -> Self {
        let mut flags = Self::empty();
        
        if attr.contains(LoongArchStage2PTEAttr::W) {
            flags |= Self::WRITE;
        }
        if !attr.contains(LoongArchStage2PTEAttr::NR) {
            flags |= Self::READ;
        }
        if !attr.contains(LoongArchStage2PTEAttr::NX) {
            flags |= Self::EXECUTE;
        }
        //todo:
        let mat = (attr.bits() & LoongArchStage2PTEAttr::MAT.bits()) >> 4;
        match mat {
            0 => flags |= Self::DEVICE, 
            1 => {},                      
            2 => flags |= Self::UNCACHED, 
            _ => {},                      
        }
        
        flags
    }
}

impl From<MappingFlags> for LoongArchStage2PTEAttr {
    fn from(flags: MappingFlags) -> Self {
        let mut attr = Self::empty();
        
        if flags.contains(MappingFlags::WRITE) {
            attr |= Self::W;
        }
        if !flags.contains(MappingFlags::READ) {
            attr |= Self::NR;
        }
        if !flags.contains(MappingFlags::EXECUTE) {
            attr |= Self::NX;
        }
        
        attr |= Self::V | Self::D;  // Valid + Dirty
        
        if flags.contains(MappingFlags::DEVICE) {
            attr |= Self::MAT_SUC; 
        } else if flags.contains(MappingFlags::UNCACHED) {
            attr |= Self::MAT_WB;  
        } else {
            attr |= Self::MAT_CC;  
        }
        
        attr
    }
}

// LoongArch64 Stage2 Paging MetaData
#[derive(Copy, Clone)]
pub struct LoongArchStage2PagingMetaData;

impl PagingMetaData for LoongArchStage2PagingMetaData {
    const LEVELS: usize = 4;
    const PA_MAX_BITS: usize = 48;
    const VA_MAX_BITS: usize = 48;
    type VirtAddr = GuestPhysAddr;
    
    fn flush_tlb(vaddr: Option<Self::VirtAddr>) {
        unsafe {
            if let Some(vaddr) = vaddr {
                core::arch::asm!("dbar 0; invtlb 0x05, $r0, {}", in(reg) vaddr.as_usize());
            } else {
                core::arch::asm!("dbar 0; invtlb 0, $r0, $r0");
            }
        }
    }
}


    // Debug implementation
impl fmt::Debug for LoongArchStage2PTE {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("LoongArchStage2PTE")
            .field("raw", &self.0)
            .field("paddr", &self.paddr())
            .field("attr", &LoongArchStage2PTEAttr::from_bits_truncate(self.0))
            .field("flags", &self.flags())
            .finish()
    }
}

pub type NestedPageTable<H> = PageTable64<LoongArchStage2PagingMetaData, LoongArchStage2PTE, H>;