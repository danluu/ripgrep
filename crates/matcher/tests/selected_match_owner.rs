use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};

use grep_matcher::SelectedMatchOwner;

std::thread_local! {
    static COUNT_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct CountingSystem;

#[global_allocator]
static GLOBAL: CountingSystem = CountingSystem;

unsafe impl GlobalAlloc for CountingSystem {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: Forward the allocator contract and unchanged layout to the
        // system allocator.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: Forward the allocator contract and unchanged layout to the
        // system allocator.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: Forward the allocator contract, pointer and layout to the
        // allocator that produced the allocation.
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn realloc(
        &self,
        ptr: *mut u8,
        layout: Layout,
        new_size: usize,
    ) -> *mut u8 {
        record_allocation();
        // SAFETY: Forward the allocator contract, pointer, layout and size to
        // the system allocator.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

fn record_allocation() {
    let active = COUNT_ALLOCATIONS.try_with(Cell::get).unwrap_or(false);
    if active {
        let _ = ALLOCATIONS.try_with(|count| {
            count.set(count.get().saturating_add(1));
        });
    }
}

struct AllocationProbe;

impl AllocationProbe {
    fn start() -> AllocationProbe {
        COUNT_ALLOCATIONS.with(|active| {
            assert!(!active.replace(true), "allocation probe reentered");
        });
        ALLOCATIONS.with(|count| count.set(0));
        AllocationProbe
    }

    fn count(&self) -> usize {
        ALLOCATIONS.with(Cell::get)
    }
}

impl Drop for AllocationProbe {
    fn drop(&mut self) {
        let _ = COUNT_ALLOCATIONS.try_with(|active| active.set(false));
    }
}

#[test]
fn identity_is_stable_across_clones_and_distinct_across_owners() {
    let owner = SelectedMatchOwner::new();
    let cloned = owner.clone();
    let distinct = SelectedMatchOwner::new();

    assert!(owner.ptr_eq(&cloned));
    assert!(!owner.ptr_eq(&distinct));
    assert!(!cloned.ptr_eq(&distinct));
}

#[test]
fn identity_generation_is_thread_safe_and_unique() {
    const THREADS: usize = 8;
    const OWNERS_PER_THREAD: usize = 256;

    let mut threads = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        threads.push(std::thread::spawn(|| {
            (0..OWNERS_PER_THREAD)
                .map(|_| SelectedMatchOwner::new())
                .collect::<Vec<_>>()
        }));
    }
    let mut owners =
        Vec::with_capacity(THREADS.checked_mul(OWNERS_PER_THREAD).unwrap());
    for thread in threads {
        owners.extend(thread.join().expect("identity worker panicked"));
    }
    for (index, owner) in owners.iter().enumerate() {
        assert!(
            owners[index + 1..].iter().all(|other| !owner.ptr_eq(other)),
            "owners {index} and a later owner share one identity",
        );
    }
}

#[cfg(target_has_atomic = "64")]
#[test]
fn identity_construction_and_clone_do_not_allocate() {
    let probe = AllocationProbe::start();
    let owner = std::hint::black_box(SelectedMatchOwner::new());
    let cloned = std::hint::black_box(owner.clone());
    std::hint::black_box((&owner, &cloned));
    let allocations = probe.count();
    drop(probe);
    assert_eq!(allocations, 0);
}
