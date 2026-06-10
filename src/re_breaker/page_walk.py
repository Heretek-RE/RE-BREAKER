"""re_breaker/page_walk.py — x86_64 virtual-to-physical address walk (v0.5.1).

Translates a guest virtual address to a guest physical address by
reading the page tables from guest physical memory. Used by
`dump_virt_range` and (in v0.5.3) `re-vm-debug.translate_virt_to_phys`.

Page-table format (x86_64, 4-level paging, 4 KiB pages):
  CR3 → PML4 table (512 × 8-byte entries, PML4E)
        → PDPT (512 × PDPTE)
             → PD  (512 × PDE, may be 1 GiB hugepage)
                  → PT  (512 × PTE, may be 2 MiB hugepage)
                        → 4 KiB physical page

Each entry is 8 bytes; bits 0 (P), 7 (PS), 12..M-1 (PFN) are
what we care about. The 9-bit PFN is at bits 12..51 (52-bit
physical address space on x86_64).

References:
  - Intel SDM Vol 3, §4.5 (32-bit paging) + §4.6 (PAE) + §4.7
    (4-level paging)
  - AMD APM Vol 2, §5.5
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional


# PTE/PDE/PDPTE/PML4E flag bits
_P = 1 << 0           # Present
_RW = 1 << 1          # Read/Write
_U = 1 << 2           # User/Supervisor
_PWT = 1 << 3
_PCD = 1 << 4
_A = 1 << 5           # Accessed
_D = 1 << 6           # Dirty
_PS = 1 << 7          # Page Size (1 = hugepage for PDE/PDPTE)
_PAT = 1 << 12        # Page Attribute Table (PDE/PTE)
_NX = 1 << 63         # No-Execute (if supported)

# 4 KiB page size
_PAGE_SIZE = 4096
_PTE_ADDR_MASK = 0x000F_FFFF_FFFF_F000  # bits 12..51


@dataclass
class PageWalkResult:
    phys_addr: int
    page_size: int  # 4096, 2*1024*1024, or 1024*1024*1024
    pml4e: int
    pdpte: int
    pde: int
    pte: int
    # Flags: P/RW/U/A/D/PS
    flags: dict[str, bool]


def _entry_to_addr(entry: int) -> int:
    """Extract the physical base address from a page-table entry."""
    return entry & _PTE_ADDR_MASK


def _flags_from_entries(*entries: int) -> dict[str, bool]:
    return {
        "present": all(e & _P for e in entries),
        "writable": any(e & _RW for e in entries),
        "user": any(e & _U for e in entries),
        "accessed": any(e & _A for e in entries),
        "dirty": any(e & _D for e in entries),
        "nx": any(bool(e & _NX) for e in entries),
    }


class PageFaultError(RuntimeError):
    """Raised when a virt→phys walk fails (no PTE / no PDE / etc.)."""
    def __init__(self, level: str, cr3: int, vaddr: int, info: str = ""):
        self.level = level
        self.cr3 = cr3
        self.vaddr = vaddr
        self.info = info
        super().__init__(f"page fault at {level} for vaddr {hex(vaddr)} (cr3={hex(cr3)}): {info}")


def walk(cr3: int, vaddr: int, phys_read) -> PageWalkResult:
    """Walk the x86_64 page tables to translate `vaddr` to a phys addr.

    Args:
        cr3: value of the guest CR3 register (the PML4 base)
        vaddr: the guest virtual address to translate
        phys_read: callable(phys_addr, size) -> bytes that reads
            `size` bytes from guest physical memory starting at
            `phys_addr`. We use `re-vm-debug`'s QEMU gdb stub or
            `re-vm-memory`'s QMP pmemsave depending on which is
            cheaper.
    """
    # CR3 has bits 12..51 = PML4 base, low 12 bits = PCID (we ignore)
    pml4_base = cr3 & _PTE_ADDR_MASK

    # Indices into the 4 page-table levels (each is 9 bits)
    pml4_idx = (vaddr >> 39) & 0x1FF
    pdpt_idx = (vaddr >> 30) & 0x1FF
    pd_idx = (vaddr >> 21) & 0x1FF
    pt_idx = (vaddr >> 12) & 0x1FF
    page_off = vaddr & 0xFFF

    # PML4E
    pml4e_bytes = phys_read(pml4_base + pml4_idx * 8, 8)
    (pml4e,) = struct.unpack("<Q", pml4e_bytes)
    if not (pml4e & _P):
        raise PageFaultError("PML4E", cr3, vaddr, f"PML4E[{pml4_idx}] not present")

    # PDPTE
    pdpt_base = _entry_to_addr(pml4e)
    pdpte_bytes = phys_read(pdpt_base + pdpt_idx * 8, 8)
    (pdpte,) = struct.unpack("<Q", pdpte_bytes)
    if not (pdpte & _P):
        raise PageFaultError("PDPTE", cr3, vaddr, f"PDPTE[{pdpt_idx}] not present")
    if pdpte & _PS:
        # 1 GiB hugepage (PS bit on PDPTE)
        phys_base = _entry_to_addr(pdpte) | (vaddr & 0x3FFF_FFFF)  # bits 30..39 preserved
        return PageWalkResult(
            phys_addr=phys_base,
            page_size=1024 * 1024 * 1024,
            pml4e=pml4e, pdpte=pdpte, pde=0, pte=0,
            flags=_flags_from_entries(pml4e, pdpte),
        )

    # PDE
    pd_base = _entry_to_addr(pdpte)
    pde_bytes = phys_read(pd_base + pd_idx * 8, 8)
    (pde,) = struct.unpack("<Q", pde_bytes)
    if not (pde & _P):
        raise PageFaultError("PDE", cr3, vaddr, f"PDE[{pd_idx}] not present")
    if pde & _PS:
        # 2 MiB hugepage (PS bit on PDE)
        phys_base = _entry_to_addr(pde) | (vaddr & 0x1F_FFFF)  # bits 21..29 preserved
        return PageWalkResult(
            phys_addr=phys_base,
            page_size=2 * 1024 * 1024,
            pml4e=pml4e, pdpte=pdpte, pde=pde, pte=0,
            flags=_flags_from_entries(pml4e, pdpte, pde),
        )

    # PTE (4 KiB page)
    pt_base = _entry_to_addr(pde)
    pte_bytes = phys_read(pt_base + pt_idx * 8, 8)
    (pte,) = struct.unpack("<Q", pte_bytes)
    if not (pte & _P):
        raise PageFaultError("PTE", cr3, vaddr, f"PTE[{pt_idx}] not present")

    phys_base = _entry_to_addr(pte)
    return PageWalkResult(
        phys_addr=phys_base + page_off,
        page_size=_PAGE_SIZE,
        pml4e=pml4e, pdpte=pdpte, pde=pde, pte=pte,
        flags=_flags_from_entries(pml4e, pdpte, pde, pte),
    )
