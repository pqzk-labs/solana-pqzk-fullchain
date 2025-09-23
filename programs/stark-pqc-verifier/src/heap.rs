//! Allocator for Solana SBF without writable ELF sections.
//!
//! No .bss/.data; allocator metadata lives at heap start;
//! default limit 32 KiB; in-place realloc and last-allocation free.
//!
//! Runtime contract: set_heap_limit_bytes(n) must match 
//! ComputeBudgetProgram.requestHeapFrame({ bytes: n }) (1024-byte multiple, max 256 KiB).

extern crate alloc;

use core::{
    alloc::{GlobalAlloc, Layout},
    cmp,
    mem,
    ptr,
};

#[cfg(any(target_arch = "bpf", target_os = "solana"))]
const HEAP_START: usize = solana_program_entrypoint::HEAP_START_ADDRESS as usize;
const DEFAULT_LIMIT_BYTES: usize = 32 * 1024;

// Offsets for the in-heap allocator metadata.
const USZ: usize = mem::size_of::<usize>();
const OFF_HEAD:      usize = 0 * USZ; // Next alloc ptr
const OFF_LIMIT:     usize = 1 * USZ; // Start + bytes
const OFF_LAST_PTR:  usize = 2 * USZ; // Last allocation ptr
const OFF_LAST_SIZE: usize = 3 * USZ; // Last allocation size
const META_SIZE:     usize = 4 * USZ; // Reserved bytes at heap start

#[inline(always)]
fn heap_start() -> usize {
    #[cfg(any(target_arch = "bpf", target_os = "solana"))] { HEAP_START }
    #[cfg(not(any(target_arch = "bpf", target_os = "solana")))] { 0x3000_0000_00 }
}

#[inline(always)]
unsafe fn read_usize(addr: usize) -> usize { (addr as *const usize).read_volatile() }

#[inline(always)]
unsafe fn write_usize(addr: usize, val: usize) { (addr as *mut usize).write_volatile(val) }

#[inline(always)]
fn align_up(x: usize, a: usize) -> usize {
    let m = a - 1;
    (x + m) & !m
}

// Lazily initializes allocator metadata on first access.
#[inline(always)]
unsafe fn ensure_inited() {
    let start = heap_start();
    let limit = read_usize(start + OFF_LIMIT);
    if limit == 0 {
        write_usize(start + OFF_HEAD,  start + META_SIZE);
        write_usize(start + OFF_LIMIT, start + DEFAULT_LIMIT_BYTES);
        write_usize(start + OFF_LAST_PTR,  0);
        write_usize(start + OFF_LAST_SIZE, 0);
    }
}

/// Sets heap byte limit, 1024-byte multiple with a minimum of 32 KiB.
#[inline]
pub fn set_heap_limit_bytes(bytes: usize) {
    unsafe {
        let start = heap_start();
        let n = cmp::max(DEFAULT_LIMIT_BYTES, bytes & !1023usize);
        if read_usize(start + OFF_HEAD) == 0 {
            // Initializes head if uninitialized (skip metadata).
            write_usize(start + OFF_HEAD, start + META_SIZE);
        }
        write_usize(start + OFF_LIMIT, start + n);
    }
}

/// Debug helper: returns (start, head, limit).
#[allow(unused)]
pub fn snapshot() -> (usize, usize, usize) {
    unsafe {
        let s = heap_start();
        (s, read_usize(s + OFF_HEAD), read_usize(s + OFF_LIMIT))
    }
}

/// Zero-sized global allocator (keeps no RW ELF sections).
pub struct BpfBumpAlloc;

unsafe impl GlobalAlloc for BpfBumpAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ensure_inited();
        let start = heap_start();
        let head  = read_usize(start + OFF_HEAD);
        let limit = read_usize(start + OFF_LIMIT);

        let align = layout.align().max(mem::align_of::<usize>());
        let size  = layout.size();
        let ptr   = align_up(head, align);
        let Some(end) = ptr.checked_add(size) else { return ptr::null_mut() };
        if end > limit { return ptr::null_mut(); }

        write_usize(start + OFF_HEAD, end);
        write_usize(start + OFF_LAST_PTR,  ptr);
        write_usize(start + OFF_LAST_SIZE, size);
        ptr as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let start = heap_start();
        let last_ptr = read_usize(start + OFF_LAST_PTR);
        let last_sz  = read_usize(start + OFF_LAST_SIZE);
        if last_ptr == (ptr as usize) && last_sz == layout.size() {
            // Performs opportunistic free (LIFO).
            write_usize(start + OFF_HEAD, last_ptr);
            write_usize(start + OFF_LAST_PTR,  0);
            write_usize(start + OFF_LAST_SIZE, 0);
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ensure_inited();
        let start    = heap_start();
        let last_ptr = read_usize(start + OFF_LAST_PTR);
        let last_sz  = read_usize(start + OFF_LAST_SIZE);

        if last_ptr == (ptr as usize) {
            let head  = read_usize(start + OFF_HEAD);
            let limit = read_usize(start + OFF_LIMIT);
            let old_end = last_ptr + last_sz;
            let Some(new_end) = last_ptr.checked_add(new_size) else { return ptr::null_mut() };

            if new_end <= old_end {
                // Shrink in place.
                write_usize(start + OFF_HEAD, new_end);
                write_usize(start + OFF_LAST_SIZE, new_size);
                return ptr;
            } else if new_end <= limit && head == old_end {
                // Grow in place.
                write_usize(start + OFF_HEAD, new_end);
                write_usize(start + OFF_LAST_SIZE, new_size);
                return ptr;
            }
        }

        // Fallback: alloc + copy.
        let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
        let new_ptr = self.alloc(new_layout);
        if new_ptr.is_null() { return ptr::null_mut() }
        let to_copy = cmp::min(layout.size(), new_size);
        ptr::copy_nonoverlapping(ptr, new_ptr, to_copy);
        new_ptr
    }
}
