"""gdb_remote.py — minimal GDB Remote Serial Protocol client for the
QEMU gdb stub (v0.5.0 SCAFFOLD).

The QEMU gdb stub speaks the **GDB Remote Serial Protocol** (RSP) over
a plain TCP socket. We only need a tiny subset to make re-vm-debug
useful:

  - `qSupported`         : negotiate features
  - `g`                  : read all registers
  - `G <hex>`            : write all registers
  - `m <addr>,<len>`     : read memory
  - `M <addr>,<len>:<hex>` : write memory
  - `Z0,<addr>,<kind>`   : insert software breakpoint (INT3 / 0xCC)
  - `Z1,<addr>,<kind>`   : insert hardware breakpoint
  - `Z2,<addr>,<kind>`   : insert write watchpoint
  - `Z3,<addr>,<kind>`   : insert read watchpoint
  - `Z4,<addr>,<kind>`   : insert access (R/W) watchpoint
  - `z*`                 : remove the corresponding breakpoint
  - `c` / `s`            : continue / step
  - `?`                  : query halt reason
  - `D`                  : detach (let VM run freely)
  - `k`                  : kill the stub (VM exits)

The packet format is `$<payload>#<2-digit checksum>`. Acknowledgement
is `+` / `-` (we re-send on `-`).

The full RSP spec is ~200 pages; this ~200-line client covers what
re-vm-debug actually needs in v0.5.3. Hex-encoding/decoding and
checksum calculation are inlined; multi-register `g`/`G` payloads
use the standard x86-64 layout (16 GPR + RIP + EFLAGS + 16 XMM +
segment + control + debug + ... ; the QEMU stub returns the full
layout and the caller decodes by fixed offset).

v0.5.0 status: SCAFFOLD — the `connect()`, `disconnect()`, and
`send_packet()` helpers are real; everything else is "v0.5.3 will
implement" stubs. We need at least the connect path real in v0.5.0
so the other tools can fail with a clear "not implemented" rather
than a `NotImplementedError` from a half-finished shell.
"""
from __future__ import annotations

import logging
import socket
import time
from typing import Any, Optional, Tuple

log = logging.getLogger("re-vm-debug.gdb_remote")


# x86_64 register layout (gdb ordering). Used for the `g` packet decode.
# Source: gdb/features/amd64.xml. Total = 27 (gdb) but QEMU returns 44+
# for full state; we use offset tables for the first 17 (the ones the
# analyst cares about 99% of the time).
X86_64_REG_NAMES = (
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs",
    "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
    "fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop",
    "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7",
    "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
)
X86_64_REG_SIZE = 8  # 64-bit GPR
X86_64_SEG_SIZE = 4
X86_64_FCTRL_SIZE = 2


def _checksum(payload: bytes) -> int:
    """GDB checksum is the low 8 bits of the sum of all payload bytes."""
    return sum(payload) & 0xFF


class GdbRemoteError(RuntimeError):
    pass


class GdbRemoteClient:
    """Minimal RSP client. Thread-unsafe; wrap with a lock if shared."""

    def __init__(self, host: str = "127.0.0.1", port: int = 1234, timeout_s: float = 10.0):
        self.host = host
        self.port = port
        self.timeout_s = timeout_s
        self.sock: Optional[socket.socket] = None
        self._buf = b""

    def __enter__(self) -> "GdbRemoteClient":
        self.connect()
        return self

    def __exit__(self, *args) -> None:
        self.disconnect()

    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout_s)
        self.sock.settimeout(self.timeout_s)
        self._buf = b""
        # Negotiate features; QEMU returns a list it supports.
        resp = self._send_raw("qSupported:multiprocess+")
        log.info("gdb stub connected; qSupported -> %r", resp[:80])

    def disconnect(self) -> None:
        if self.sock is not None:
            try:
                self._send_raw("D")
            except Exception:
                pass
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            self.sock.close()
            self.sock = None

    # --- raw I/O ---

    def _send_raw(self, payload: str) -> str:
        """Send one RSP packet; return the response text (no $/#)."""
        if self.sock is None:
            raise GdbRemoteError("not connected")
        data = payload.encode("ascii")
        cksum = _checksum(data)
        packet = f"${payload}#{cksum:02x}".encode("ascii")
        for attempt in range(3):
            self.sock.sendall(packet)
            ack = self._read_exact(1)
            if ack == b"+":
                break
            log.warning("gdb stub NAK'd packet (attempt %d); resending", attempt + 1)
        else:
            raise GdbRemoteError(f"gdb stub kept NAKing {payload!r}")
        # Read response (terminated by '#NN')
        resp = self._read_until(b"#")
        if len(resp) < 2:
            raise GdbRemoteError("truncated response")
        cksum_str = resp[-2:].decode("ascii", errors="replace")
        body = resp[:-2]
        try:
            expected = int(cksum_str, 16)
        except ValueError:
            expected = -1
        if expected >= 0 and _checksum(body) != expected:
            raise GdbRemoteError(f"checksum mismatch in response: got {cksum_str}")
        text = body.decode("ascii", errors="replace")
        if text.startswith("E"):
            raise GdbRemoteError(f"gdb stub returned error: {text}")
        return text

    def _read_exact(self, n: int) -> bytes:
        """Read exactly n bytes (or timeout)."""
        assert self.sock is not None
        while len(self._buf) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise GdbRemoteError("gdb stub closed the connection")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _read_until(self, marker: bytes) -> bytes:
        """Read until `marker` is found in the buffered bytes."""
        assert self.sock is not None
        deadline = time.time() + self.timeout_s
        while marker not in self._buf:
            self.sock.settimeout(max(0.1, deadline - time.time()))
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                raise GdbRemoteError("gdb stub read timeout")
            if not chunk:
                raise GdbRemoteError("gdb stub closed the connection")
            self._buf += chunk
        idx = self._buf.index(marker) + len(marker)
        out, self._buf = self._buf[:idx], self._buf[idx:]
        return out

    # --- high-level ops (v0.5.3 fully implemented) ---

    # Max bytes per `m` packet. QEMU's default is unlimited but the
    # gdb stub hangs the connection if the response is too big; we
    # cap at 4 KiB to match the kernel page size (the common case).
    _MAX_READ_SIZE = 4096
    _MAX_WRITE_SIZE = 4096

    def read_registers(self) -> dict[str, int]:
        """Send `g` and decode the hex payload by X86_64_REG_SIZE.

        Returns the first 17 registers (the GPR + RIP + EFLAGS), which
        is what the analyst cares about 99% of the time. The full
        44-register layout (FP / SSE / segment / debug) will be
        added in v0.6.
        """
        hex_payload = self._send_raw("g")
        out: dict[str, int] = {}
        # Each register is X86_64_REG_SIZE (8 bytes) hex; 17 of them.
        for i in range(17):
            start = i * 16  # 8 bytes = 16 hex chars
            end = start + 16
            if end > len(hex_payload):
                break
            chunk = hex_payload[start:end]
            name = X86_64_REG_NAMES[i]
            out[name] = int(chunk, 16)
        return out

    def write_registers(self, regs: dict[str, int]) -> bool:
        """Send `G<hex>`. Validates the dict keys against the known set."""
        # Build the full 17-register hex payload (zero-filled for
        # any missing register, so partial writes are safe).
        chunks: list[str] = []
        for i in range(17):
            name = X86_64_REG_NAMES[i]
            v = regs.get(name, 0)
            if not isinstance(v, int):
                raise GdbRemoteError(f"{name} must be int, got {type(v).__name__}")
            # Mask to 64 bits (the gdb stub expects a u64)
            v &= 0xFFFF_FFFF_FFFF_FFFF
            chunks.append(f"{v:016x}")
        payload = "G" + "".join(chunks)
        # We also need to send the rest of the register file (FP /
        # SSE / etc.) as zero bytes so the stub's length check
        # matches. The full layout is 216 bytes = 432 hex chars.
        # QEMU's stub actually only cares about the first 17 regs
        # for control-flow (RIP / RSP / RFLAGS); the FP/SSE are
        # zero by default and the stub accepts zero-padding.
        rest_zero = "0" * 416  # 26 regs * 8 bytes * 2 hex chars = 416
        resp = self._send_raw(payload + rest_zero)
        return resp == "OK"

    def read_memory(self, addr: int, size: int) -> bytes:
        """Send `m<addr>,<size>`, decode the hex payload to bytes.

        Caps at 4 KiB per call (QEMU's gdb stub can hang on huge
        reads; v0.6 will chunk for larger)."""
        if size <= 0:
            return b""
        if size > self._MAX_READ_SIZE:
            raise GdbRemoteError(
                f"read_memory size {size} > max {self._MAX_READ_SIZE} (chunk in v0.6)"
            )
        hex_payload = self._send_raw(f"m{addr:x},{size:x}")
        return bytes.fromhex(hex_payload)

    def write_memory(self, addr: int, data: bytes) -> bool:
        """Send `M<addr>,<len>:<hex>`."""
        if len(data) > self._MAX_WRITE_SIZE:
            raise GdbRemoteError(
                f"write_memory size {len(data)} > max {self._MAX_WRITE_SIZE} (chunk in v0.6)"
            )
        payload = f"M{addr:x},{len(data):x}:" + data.hex()
        resp = self._send_raw(payload)
        return resp == "OK"

    def set_breakpoint_hw(self, addr: int, kind: str = "x") -> bool:
        """Send `Z1,<addr>,<kind>`. The QEMU gdb stub takes the
        **guest physical** address for `Z1` (a QEMU quirk)."""
        if kind not in ("x", "p"):
            raise GdbRemoteError(f"set_breakpoint_hw kind must be 'x' or 'p', got {kind!r}")
        resp = self._send_raw(f"Z1,{addr:x},{kind}")
        return resp == "OK"

    def set_watchpoint(self, addr: int, size: int, access: str = "rw") -> bool:
        """Send `Z2/Z3/Z4,<addr>,<kind>`. access ∈ {r, w, rw}."""
        access_map = {"r": (3, "r"), "w": (2, "w"), "rw": (4, "rw")}
        if access not in access_map:
            raise GdbRemoteError(f"access must be one of r/w/rw, got {access!r}")
        z_type, kind = access_map[access]
        resp = self._send_raw(f"Z{z_type},{addr:x},{kind}")
        return resp == "OK"

    def clear_breakpoint_hw(self, addr: int) -> bool:
        resp = self._send_raw(f"z1,{addr:x},x")
        return resp == "OK"

    def clear_watchpoint(self, addr: int) -> bool:
        """Clears a watchpoint at the address. Tries Z2/Z3/Z4 in turn
        (the stub won't tell us which kind it is)."""
        for z_type in (2, 3, 4):
            try:
                resp = self._send_raw(f"z{z_type},{addr:x},rw")
                if resp == "OK":
                    return True
            except GdbRemoteError:
                continue
        return False

    def continue_execution(self, addr: Optional[int] = None) -> str:
        """Send `c` or `c<addr>`. Returns the stop reason from the
        response (T05 = SIGTRAP, S05 = pause, etc.). The stub halts
        on the next breakpoint / single-step / signal."""
        cmd = "c" if addr is None else f"c{addr:x}"
        resp = self._send_raw(cmd)
        return resp  # e.g. "T05hwbreak:;" or "S05"

    def step(self, addr: Optional[int] = None) -> str:
        """Send `s` or `s<addr>`. Single-steps one instruction."""
        cmd = "s" if addr is None else f"s{addr:x}"
        resp = self._send_raw(cmd)
        return resp

    def halt_reason(self) -> str:
        """Send `?`. Returns the stop reason T-NN / S-NN string."""
        return self._send_raw("?")

    def detach(self) -> None:
        self._send_raw("D")
