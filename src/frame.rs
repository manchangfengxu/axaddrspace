use core::marker::PhantomData;

use axerrno::{AxResult, ax_err_type};

pub(crate) use memory_addr::PAGE_SIZE_4K as PAGE_SIZE;

use crate::{AxMmHal, HostPhysAddr};

/// A physical frame which will be automatically deallocated when dropped.
///
/// The frame is allocated using the [`AxMmHal`] implementation. The size of the frame is likely to
/// be 4 KiB but the actual size is determined by the [`AxMmHal`] implementation.
#[derive(Debug)]
pub struct PhysFrame<H: AxMmHal> {
    start_paddr: Option<HostPhysAddr>,
    _marker: PhantomData<H>,
}

impl<H: AxMmHal> PhysFrame<H> {
    /// Allocate a [`PhysFrame`].
    pub fn alloc() -> AxResult<Self> {
        let start_paddr = H::alloc_frame()
            .ok_or_else(|| ax_err_type!(NoMemory, "allocate physical frame failed"))?;
        assert_ne!(start_paddr.as_usize(), 0);
        Ok(Self {
            start_paddr: Some(start_paddr),
            _marker: PhantomData,
        })
    }

    /// Allocate a [`PhysFrame`] and fill it with zeros.
    pub fn alloc_zero() -> AxResult<Self> {
        let mut f = Self::alloc()?;
        f.fill(0);
        Ok(f)
    }

    /// Create an uninitialized [`PhysFrame`].
    ///
    /// # Safety
    ///
    /// The caller must ensure that the [`PhysFrame`] is only used as a placeholder and never
    /// accessed.
    pub const unsafe fn uninit() -> Self {
        Self {
            start_paddr: None,
            _marker: PhantomData,
        }
    }

    /// Get the starting physical address of the frame.
    pub fn start_paddr(&self) -> HostPhysAddr {
        self.start_paddr.expect("uninitialized PhysFrame")
    }

    /// Get a mutable pointer to the frame.
    pub fn as_mut_ptr(&self) -> *mut u8 {
        H::phys_to_virt(self.start_paddr()).as_mut_ptr()
    }

    /// Fill the frame with a byte. Works only when the frame is 4 KiB in size.
    pub fn fill(&mut self, byte: u8) {
        unsafe { core::ptr::write_bytes(self.as_mut_ptr(), byte, PAGE_SIZE) }
    }
}

impl<H: AxMmHal> Drop for PhysFrame<H> {
    fn drop(&mut self) {
        if let Some(start_paddr) = self.start_paddr {
            H::dealloc_frame(start_paddr);
            debug!("[AxVM] deallocated PhysFrame({:#x})", start_paddr);
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{HostPhysAddr, HostVirtAddr};
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use lazy_static::lazy_static;
    use spin::Mutex;

    // Static variables to simulate global state of a memory allocator in tests.
    static NEXT_PADDR: AtomicUsize = AtomicUsize::new(0x1000);

    lazy_static! {
        // Simulates the actual physical memory block used for allocation.
        static ref MEMORY: Mutex<[u8; 0x10000]> = Mutex::new([0; 0x10000]); // 64KB for testing
    }
    lazy_static! {
        // Global mutex to enforce serial execution for tests that modify shared state.
        // This ensures test isolation and prevents race conditions between tests.
        static ref TEST_MUTEX: Mutex<()> = Mutex::new(());
    }
    static DEALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

    // Flag to simulate memory allocation failures for testing error handling.
    static ALLOC_FAIL: AtomicBool = AtomicBool::new(false);

    #[derive(Debug)]
    struct MockHal {}

    impl AxMmHal for MockHal {
        fn alloc_frame() -> Option<HostPhysAddr> {
            // Use a static mutable variable to control alloc_fail state
            if ALLOC_FAIL.load(Ordering::SeqCst) {
                return None;
            }

            let paddr = NEXT_PADDR.fetch_add(PAGE_SIZE, Ordering::SeqCst);
            if paddr as usize >= MEMORY.lock().len() {
                return None;
            }
            Some(HostPhysAddr::from_usize(paddr))
        }

        fn dealloc_frame(paddr: HostPhysAddr) {
            DEALLOC_COUNT.fetch_add(1, Ordering::SeqCst);
            let _ = paddr;
        }
        // In this test mock, the "virtual address" is simply a direct pointer
        // to the corresponding location within the `MEMORY` array.
        // It simulates a physical-to-virtual memory mapping for test purposes.
        fn phys_to_virt(paddr: HostPhysAddr) -> HostVirtAddr {
            let offset = paddr.as_usize() - 0x1000;
            HostVirtAddr::from_usize(MEMORY.lock().as_ptr() as usize + offset)
        }

        fn virt_to_phys(vaddr: HostVirtAddr) -> HostPhysAddr {
            let offset = vaddr.as_usize() - MEMORY.lock().as_ptr() as usize;
            HostPhysAddr::from_usize(0x1000 + offset)
        }
    }

    impl MockHal {
        fn set_alloc_fail(fail: bool) {
            ALLOC_FAIL.store(fail, Ordering::SeqCst);
        }
    }

    #[test]
    fn test_alloc_dealloc_cycle() {
        let _guard = TEST_MUTEX.lock();
        DEALLOC_COUNT.store(0, Ordering::SeqCst);
        {
            let frame = PhysFrame::<MockHal>::alloc()
                .unwrap_or_else(|e| panic!("Failed to allocate frame: {:?}", e));
            assert_ne!(frame.start_paddr().as_usize(), 0);
            // frame is dropped here, dealloc_frame should be called
        }
        assert_eq!(DEALLOC_COUNT.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_alloc_zero() {
        let _guard = TEST_MUTEX.lock();
        let frame = PhysFrame::<MockHal>::alloc_zero()
            .unwrap_or_else(|e| panic!("Failed to allocate zero frame: {:?}", e));
        assert_ne!(frame.start_paddr().as_usize(), 0);
        let ptr = frame.as_mut_ptr();
        let mem = MEMORY.lock();
        for i in 0..PAGE_SIZE {
            assert_eq!(unsafe { *ptr.add(i) }, 0);
        }
        drop(mem);
    }

    #[test]
    fn test_fill_operation() {
        let _guard = TEST_MUTEX.lock();
        let mut frame = PhysFrame::<MockHal>::alloc()
            .unwrap_or_else(|e| panic!("Failed to allocate frame: {:?}", e));
        frame.fill(0xAA);
        let ptr = frame.as_mut_ptr();
        let mem = MEMORY.lock();
        for i in 0..PAGE_SIZE {
            assert_eq!(unsafe { *ptr.add(i) }, 0xAA);
        }
        drop(mem);
    }

    #[test]
    #[should_panic(expected = "uninitialized PhysFrame")]
    fn test_uninit_access() {
        let frame = unsafe { PhysFrame::<MockHal>::uninit() };
        frame.start_paddr(); // This should panic
    }

    #[test]
    fn test_alloc_no_memory() {
        let _guard = TEST_MUTEX.lock();
        DEALLOC_COUNT.store(0, Ordering::SeqCst);
        {
            MockHal::set_alloc_fail(true);
            let result = PhysFrame::<MockHal>::alloc();
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), axerrno::AxError::NoMemory));
            MockHal::set_alloc_fail(false); // Reset for other tests
        }
        assert_eq!(DEALLOC_COUNT.load(Ordering::SeqCst), 0);
    }
}
