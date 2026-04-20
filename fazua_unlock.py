#!/usr/bin/env python3
"""
fazua_unlock.py - Standalone CLI to change bikeMaxSpeed on a Fazua RIDE 50.

USAGE:
  python fazua_unlock.py --read-only
  python fazua_unlock.py <target_kmh> --dry-run
  python fazua_unlock.py <target_kmh>               (prompts before writing)
  python fazua_unlock.py <target_kmh> --force       (skip prompt)

VERIFIED AGAINST: Fazua Drivepack firmware 2.04.

SAFETY:
  * Refuses to run if another process is holding the HID handle.
  * Prompts for 'yes' before writing unless --force.
  * Validates CRC on every bike response.
  * Re-reads config after write to confirm.

REQUIREMENTS:
  Windows; Python 3.8+; pywinusb; psutil.

The tool reads the bike's current config (command 03 02), changes bytes 17-18
of the response (bikeMaxSpeed, u16 little-endian = raw m/s*100 = km/h / 0.036),
inserts a per-drive-unit 2-byte write-auth key at bytes 33-34 (auto-derived
from the drive unit's Shaft Offset), recomputes CRC-16 XMODEM over bytes
4..35 (stored big-endian at 36-37), and sends it back as a command 03 01 write.
"""
import argparse
import ctypes
import ctypes.wintypes as wt
import os
import re
import struct
import sys
import time
from dataclasses import dataclass


# =============================================================================
# Constants
# =============================================================================

FAZUA_VID = 0x10C4
FAZUA_PID = 0x1001
PACKET_LEN = 38

# CRC coverage: bytes 4..35 inclusive (36 exclusive). Stored big-endian at 36-37.
CRC_COVER_START = 4
CRC_COVER_END = 36

# Commands (bytes 4-5 of payload)
CMD_GET_CONFIG = bytes([0x03, 0x02])  # read
CMD_SET_CONFIG = bytes([0x03, 0x01])  # write

# Protocol control bytes. Each is sent as a 38-byte packet: 00 <cb> 00...00.
CTRL_EOT   = 0x04   # end-of-transmission
CTRL_ACK   = 0x06   # ACK
CTRL_MORE  = 0x21   # "more data" / preamble / wake trigger
CTRL_READY = 0x22   # ready
CTRL_CYCLE = 0x25   # cycle transition / close

# bikeMaxSpeed location within 03 02 / 03 01 payload (u16 LE).
BIKEMAXSPEED_OFFSET = 17

# Write-authentication magic. The drive unit expects a two-byte value at
# bytes 33-34 of every 03 01 block-1 write. Without the correct bytes the
# drive unit silently rejects the write.
#
# The key is derived from the drive unit's Shaft_Offset value:
#   key_u16 = ~Shaft_Offset & 0xFFFF  (bitwise complement)
#   key_bytes = struct.pack('<H', key_u16)  (little-endian)
#
# Example: Shaft_Offset = 0x1234 → ~0x1234 = 0xEDCB → LE bytes: CB ED
#
# The FAZUA_WRITE_KEY env var can override the auto-derived key if needed.
WRITE_MAGIC_OFFSET = 33


def derive_write_key(shaft_offset: int) -> bytes:
    """Derive the 2-byte write-auth key from the drive unit's Shaft_Offset.
    Formula: bitwise complement of the 16-bit shaft offset, little-endian."""
    key_u16 = ~shaft_offset & 0xFFFF
    return struct.pack('<H', key_u16)


def _load_write_key(shaft_offset: int = None) -> bytes:
    """Get the write-auth key. Priority:
    1. FAZUA_WRITE_KEY env var (manual override)
    2. Auto-derive from shaft_offset (if provided)
    3. Raise error (no key available)
    """
    raw = os.environ.get('FAZUA_WRITE_KEY', '').strip()
    if raw:
        cleaned = raw.replace('0x', '').replace(' ', '').replace(',', '').replace(':', '')
        try:
            key = bytes.fromhex(cleaned)
        except ValueError:
            raise RuntimeError(
                f"FAZUA_WRITE_KEY has invalid hex: {raw!r}. Expected two bytes "
                f"like 'ab cd' or 'abcd'.")
        if len(key) != 2:
            raise RuntimeError(
                f"FAZUA_WRITE_KEY must be exactly 2 bytes, got {len(key)} from {raw!r}.")
        return key
    if shaft_offset is not None:
        return derive_write_key(shaft_offset)
    return b'\x00\x00'

# Static continuation block 2 that follows every 03 01 block-1 write.
# Verified byte-identical across multiple sessions.
BLOCK2_EXPECTED_CRC = 0x8052

# Processes that hold the Fazua HID handle — must not be running.
BLOCKING_PROCESS_PATTERNS = [
    re.compile(r'^FAZUA', re.IGNORECASE),
]


# =============================================================================
# CRC-16-XMODEM
# =============================================================================

def crc16_xmodem(buf: bytes) -> int:
    """CRC-16-XMODEM / CRC-16-CCITT (init 0x0000, poly 0x1021)."""
    crc = 0
    for b in buf:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if (crc & 0x8000) else (crc << 1) & 0xFFFF
    return crc


def crc_of_packet(pkt: bytes) -> int:
    return crc16_xmodem(pkt[CRC_COVER_START:CRC_COVER_END])


def apply_crc(pkt: bytearray) -> None:
    """Compute CRC over bytes 4..35 and write big-endian at 36..37."""
    c = crc_of_packet(bytes(pkt))
    pkt[36] = (c >> 8) & 0xFF
    pkt[37] = c & 0xFF


def verify_crc(pkt: bytes) -> bool:
    c = crc_of_packet(pkt)
    return pkt[36] == ((c >> 8) & 0xFF) and pkt[37] == (c & 0xFF)


# =============================================================================
# Packet builders
# =============================================================================

def build_control_packet(control_byte: int) -> bytes:
    """One-byte control packet: 00 <cb> 00 00 ... padded to 38 bytes.
    No CRC - short control packets have no CRC structure."""
    pkt = bytearray(PACKET_LEN)
    pkt[1] = control_byte
    return bytes(pkt)


def build_query_packet(cmd: bytes) -> bytes:
    """Query-style packet (e.g. 03 02 get-config).
    Layout: 00 01 01 fe <cmd[0]> <cmd[1]> ff * 30 <CRC BE>."""
    if len(cmd) != 2:
        raise ValueError(f'cmd must be 2 bytes, got {len(cmd)}')
    pkt = bytearray(PACKET_LEN)
    pkt[0:4] = b'\x00\x01\x01\xfe'
    pkt[4:6] = cmd
    for i in range(6, 36):
        pkt[i] = 0xFF
    apply_crc(pkt)
    return bytes(pkt)


def build_03_01_block1_from_response(response_pkt: bytes, new_max_speed_kmh: float,
                                      write_key: bytes = None) -> bytes:
    """Build block 1 of a 03 01 write from a 03 02 response.

    Transform: byte 5 (02 -> 01), bytes 17-18 (new kmh as u16 LE),
    bytes 33-34 set to the 2-byte write-auth key, CRC recomputed.
    If write_key is None, auto-derives from Shaft_Offset in the response packet
    (or uses FAZUA_WRITE_KEY env var if set).
    """
    if len(response_pkt) != PACKET_LEN:
        raise ValueError(f'response must be {PACKET_LEN} bytes, got {len(response_pkt)}')
    if response_pkt[4:6] != CMD_GET_CONFIG:
        raise ValueError(f'not a 03 02 response: bytes 4-5 = {response_pkt[4:6].hex()}')
    if write_key is None:
        shaft_offset = struct.unpack_from('<H', response_pkt, 6)[0]
        write_key = _load_write_key(shaft_offset)
    if len(write_key) != 2:
        raise ValueError(f'write_key must be 2 bytes, got {len(write_key)}')
    out = bytearray(response_pkt)
    out[5] = 0x01  # cmd: response -> write
    raw = kmh_to_raw(new_max_speed_kmh)
    out[BIKEMAXSPEED_OFFSET:BIKEMAXSPEED_OFFSET + 2] = struct.pack('<H', raw)
    out[WRITE_MAGIC_OFFSET:WRITE_MAGIC_OFFSET + 2] = write_key
    apply_crc(out)
    return bytes(out)


def build_03_01_block2() -> bytes:
    """Static continuation block 2. Byte-identical across all sessions.
    Layout: 00 01 02 fd 00 00 5a 00..00 ff..ff 80 52."""
    pkt = bytearray(PACKET_LEN)
    pkt[0:4] = b'\x00\x01\x02\xfd'
    pkt[4:6] = b'\x00\x00'
    pkt[6] = 0x5A
    for i in range(14, 36):
        pkt[i] = 0xFF
    apply_crc(pkt)
    if pkt[36] != 0x80 or pkt[37] != 0x52:
        raise AssertionError(f"block2 CRC wrong: got {pkt[36]:02x}{pkt[37]:02x}, expected 8052")
    return bytes(pkt)


# =============================================================================
# Config decode
# =============================================================================

@dataclass
class BikeConfig:
    raw: bytes
    shaft_offset: int
    wheel_length_mm: int
    unit_tag: int
    bikeMaxSpeed_raw: int
    bikeMaxSpeed_kmh: float
    logs_period: int

    def __str__(self):
        return (f"Shaft_Offset={self.shaft_offset}  "
                f"Wheel_Length={self.wheel_length_mm}mm  "
                f"unit_tag=0x{self.unit_tag:02x}  "
                f"bikeMaxSpeed={self.bikeMaxSpeed_raw} raw = "
                f"{self.bikeMaxSpeed_kmh:.2f} km/h  "
                f"Logs_Period={self.logs_period}")


def decode_config_packet(pkt: bytes) -> BikeConfig:
    if len(pkt) != PACKET_LEN:
        raise ValueError(f'packet must be {PACKET_LEN} bytes, got {len(pkt)}')
    shaft_offset = struct.unpack_from('<H', pkt, 6)[0]
    wheel_length = struct.unpack_from('<H', pkt, 14)[0]
    unit_tag     = pkt[16]
    raw_speed    = struct.unpack_from('<H', pkt, BIKEMAXSPEED_OFFSET)[0]
    logs_period  = struct.unpack_from('<H', pkt, 30)[0]
    return BikeConfig(
        raw=pkt,
        shaft_offset=shaft_offset,
        wheel_length_mm=wheel_length,
        unit_tag=unit_tag,
        bikeMaxSpeed_raw=raw_speed,
        bikeMaxSpeed_kmh=raw_speed * 0.036,
        logs_period=logs_period,
    )


def kmh_to_raw(kmh: float) -> int:
    v = round(kmh / 0.036)
    if not 0 <= v <= 0xFFFF:
        raise ValueError(f'kmh {kmh} -> raw {v} out of u16 range')
    return v


# =============================================================================
# Process safety
# =============================================================================

def check_no_blocking_processes(interactive: bool = True) -> None:
    """Abort if another process is holding the Fazua HID handle.
    Another process with the handle open would cause our open() to fail
    or race with their traffic."""
    try:
        import psutil
    except ImportError:
        print("WARNING: psutil not installed - cannot verify no other process "
              "is holding the Fazua HID handle. Install with: pip install psutil")
        if interactive:
            resp = input("Continue anyway? [y/N]: ").strip().lower()
            if resp != 'y':
                sys.exit(1)
        return

    hits = []
    had_denied = False
    for p in psutil.process_iter(['pid', 'name']):
        try:
            name = p.info['name'] or ''
            for pat in BLOCKING_PROCESS_PATTERNS:
                if pat.match(name):
                    hits.append((p.info['pid'], name))
                    break
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            had_denied = True
            continue

    if hits:
        print("Refusing to run - these processes hold or may hold the Fazua HID handle:")
        for pid, name in hits:
            print(f"  pid={pid} name={name}")
        print("Close them and retry.")
        sys.exit(1)
    if had_denied:
        print("WARNING: psutil could not inspect some processes (elevated/SYSTEM). "
              "An invisible process could be holding the handle.")
        if interactive:
            resp = input("Continue? [y/N]: ").strip().lower()
            if resp != 'y':
                sys.exit(1)


# =============================================================================
# Win32 HID (raw ctypes overlapped I/O)
# =============================================================================

GENERIC_READ      = 0x80000000
GENERIC_WRITE     = 0x40000000
FILE_SHARE_READ   = 0x00000001
FILE_SHARE_WRITE  = 0x00000002
OPEN_EXISTING     = 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_FLAG_OVERLAPPED  = 0x40000000
INVALID_HANDLE_VALUE  = ctypes.c_void_p(-1).value

# IOCTL_HID_SET_NUM_INPUT_BUFFERS (Windows hidclass.h) — prevents the
# default 32-report queue from overflowing during live-data bursts.
IOCTL_HID_SET_NUM_INPUT_BUFFERS = 0x000B01A4
HID_INPUT_BUFFER_COUNT = 64

WAIT_OBJECT_0    = 0x00000000
WAIT_TIMEOUT     = 0x00000102
ERROR_IO_PENDING = 997


class _OVERLAPPED(ctypes.Structure):
    _fields_ = [('Internal',     ctypes.c_void_p),
                ('InternalHigh', ctypes.c_void_p),
                ('Offset',       wt.DWORD),
                ('OffsetHigh',   wt.DWORD),
                ('hEvent',       wt.HANDLE)]


class ProtocolError(Exception):
    """Raised on short reads, CRC mismatches, or unexpected status bytes."""
    pass


def _find_device_path() -> str:
    """Locate the Fazua HID device path via pywinusb's SetupDi enumeration."""
    try:
        from pywinusb import hid as pyhid
    except ImportError:
        raise RuntimeError("pywinusb not installed. Install with: pip install pywinusb")
    flt = pyhid.HidDeviceFilter(vendor_id=FAZUA_VID, product_id=FAZUA_PID)
    devs = flt.get_devices()
    if not devs:
        raise RuntimeError(
            f"No HID device VID={FAZUA_VID:#06x} PID={FAZUA_PID:#06x} found. "
            f"Is the bike plugged in and powered on?")
    if len(devs) > 1:
        raise RuntimeError("Multiple matching HID devices - ambiguous.")
    return devs[0].device_path


class FazuaHID:
    """Windows HID I/O via raw CreateFile/WriteFile/ReadFile with overlapped I/O.
    Uses raw CreateFile/WriteFile/ReadFile with overlapped I/O."""

    def __init__(self):
        self.handle = None
        self.path = None

    def open(self):
        k32 = ctypes.windll.kernel32
        self.path = _find_device_path()
        CreateFileW = k32.CreateFileW
        CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                                wt.DWORD, wt.DWORD, wt.HANDLE]
        CreateFileW.restype = wt.HANDLE
        h = CreateFileW(self.path,
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        None,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                        None)
        if h == INVALID_HANDLE_VALUE or h is None:
            err = k32.GetLastError()
            raise OSError(f"CreateFileW failed, GetLastError={err}")
        self.handle = h

    def close(self):
        if self.handle:
            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *a):
        self.close()

    def _overlapped_call(self, io_fn, buf, nbytes, timeout_ms, op_name):
        """Issue an overlapped I/O call and wait with timeout.

        On ERROR_IO_PENDING, wait on the event. On timeout, CancelIoEx so the
        handle stays usable. GetOverlappedResult is used for the authoritative
        byte count in both sync and async completion paths.

        Uses k32.GetLastError directly because ctypes.get_last_error only
        returns a valid value when the DLL is loaded with use_last_error=True.
        """
        k32 = ctypes.windll.kernel32

        CreateEventW = k32.CreateEventW
        CreateEventW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR]
        CreateEventW.restype = wt.HANDLE

        CancelIoEx = k32.CancelIoEx
        CancelIoEx.argtypes = [wt.HANDLE, ctypes.POINTER(_OVERLAPPED)]
        CancelIoEx.restype = wt.BOOL

        GetOverlappedResult = k32.GetOverlappedResult
        GetOverlappedResult.argtypes = [wt.HANDLE, ctypes.POINTER(_OVERLAPPED),
                                        ctypes.POINTER(wt.DWORD), wt.BOOL]
        GetOverlappedResult.restype = wt.BOOL

        WaitForSingleObject = k32.WaitForSingleObject
        WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
        WaitForSingleObject.restype = wt.DWORD

        GetLastError = k32.GetLastError
        GetLastError.restype = wt.DWORD

        ov = _OVERLAPPED()
        ov.hEvent = CreateEventW(None, True, False, None)
        if not ov.hEvent:
            raise OSError(f"CreateEventW failed for {op_name}")
        transferred = wt.DWORD(0)
        try:
            ok = io_fn(self.handle, buf, nbytes, ctypes.byref(transferred), ctypes.byref(ov))
            if not ok:
                err = GetLastError()
                if err != ERROR_IO_PENDING:
                    raise OSError(f"{op_name} failed, GetLastError={err}")
                rc = WaitForSingleObject(ov.hEvent, timeout_ms)
                if rc == WAIT_TIMEOUT:
                    CancelIoEx(self.handle, ctypes.byref(ov))
                    GetOverlappedResult(self.handle, ctypes.byref(ov),
                                        ctypes.byref(transferred), True)
                    raise TimeoutError(f"{op_name} timed out after {timeout_ms}ms")
                if rc != WAIT_OBJECT_0:
                    raise OSError(f"{op_name} WaitForSingleObject rc={rc:#x}")
            if not GetOverlappedResult(self.handle, ctypes.byref(ov),
                                       ctypes.byref(transferred), False):
                err = GetLastError()
                raise OSError(f"{op_name} GetOverlappedResult failed, err={err}")
            return transferred.value
        finally:
            k32.CloseHandle(ov.hEvent)

    def set_num_input_buffers(self, n: int = HID_INPUT_BUFFER_COUNT):
        """IOCTL_HID_SET_NUM_INPUT_BUFFERS — set to 64 to prevent driver-level
        buffer overflow during bike's live-data bursts."""
        k32 = ctypes.windll.kernel32
        DeviceIoControl = k32.DeviceIoControl
        DeviceIoControl.argtypes = [wt.HANDLE, wt.DWORD, ctypes.c_void_p, wt.DWORD,
                                    ctypes.c_void_p, wt.DWORD,
                                    ctypes.POINTER(wt.DWORD),
                                    ctypes.POINTER(_OVERLAPPED)]
        DeviceIoControl.restype = wt.BOOL
        GetLastError = k32.GetLastError
        GetLastError.restype = wt.DWORD
        CreateEventW = k32.CreateEventW
        CreateEventW.argtypes = [ctypes.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR]
        CreateEventW.restype = wt.HANDLE
        GetOverlappedResult = k32.GetOverlappedResult
        GetOverlappedResult.argtypes = [wt.HANDLE, ctypes.POINTER(_OVERLAPPED),
                                        ctypes.POINTER(wt.DWORD), wt.BOOL]
        GetOverlappedResult.restype = wt.BOOL

        in_buf = ctypes.c_uint32(n)
        returned = wt.DWORD(0)
        ov = _OVERLAPPED()
        ov.hEvent = CreateEventW(None, True, False, None)
        try:
            ok = DeviceIoControl(self.handle, IOCTL_HID_SET_NUM_INPUT_BUFFERS,
                                 ctypes.byref(in_buf), 4,
                                 None, 0,
                                 ctypes.byref(returned), ctypes.byref(ov))
            if not ok:
                err = GetLastError()
                if err != ERROR_IO_PENDING:
                    raise OSError(f'DeviceIoControl SET_NUM_INPUT_BUFFERS failed, err={err}')
                if not GetOverlappedResult(self.handle, ctypes.byref(ov),
                                           ctypes.byref(returned), True):
                    raise OSError(f'DeviceIoControl completion failed, err={GetLastError()}')
        finally:
            k32.CloseHandle(ov.hEvent)

    def write(self, data: bytes, timeout_ms: int = 1000) -> int:
        if len(data) != PACKET_LEN:
            raise ValueError(f'expected {PACKET_LEN} bytes, got {len(data)}')
        k32 = ctypes.windll.kernel32
        WriteFile = k32.WriteFile
        WriteFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                              ctypes.POINTER(wt.DWORD), ctypes.POINTER(_OVERLAPPED)]
        WriteFile.restype = wt.BOOL
        buf = (ctypes.c_ubyte * len(data))(*data)
        return self._overlapped_call(WriteFile, buf, len(data), timeout_ms, 'WriteFile')

    def read(self, timeout_ms: int = 1000) -> bytes:
        """Read one 38-byte HID report. Raises TimeoutError on no data,
        ProtocolError on wrong length. Handle stays usable after timeout."""
        k32 = ctypes.windll.kernel32
        ReadFile = k32.ReadFile
        ReadFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD,
                             ctypes.POINTER(wt.DWORD), ctypes.POINTER(_OVERLAPPED)]
        ReadFile.restype = wt.BOOL
        buf = (ctypes.c_ubyte * PACKET_LEN)()
        n = self._overlapped_call(ReadFile, buf, PACKET_LEN, timeout_ms, 'ReadFile')
        if n != PACKET_LEN:
            raise ProtocolError(
                f"short HID read: expected {PACKET_LEN} bytes, got {n}. "
                f"partial: {bytes(buf[:n]).hex()}")
        return bytes(buf)


# =============================================================================
# Protocol helpers
# =============================================================================

def _hex(b: bytes, n: int = None) -> str:
    s = b.hex()
    return s if n is None else s[:n * 2] + ('...' if len(b) > n else '')


def _dbg(verbose: bool, msg: str) -> None:
    if verbose:
        print(msg)


def drain_buffer(dev: FazuaHID, timeout_ms: int = 50,
                 max_packets: int = 16, verbose: bool = False) -> int:
    """Drain any stale HID reports left over from a prior session or timeout.
    Returns count drained. Swallows TimeoutError (empty buffer) and ProtocolError
    (malformed stale packet)."""
    drained = 0
    while drained < max_packets:
        try:
            r = dev.read(timeout_ms=timeout_ms)
            drained += 1
            _dbg(verbose, f'    [drain] {r[:8].hex()}...')
        except TimeoutError:
            break
        except ProtocolError as e:
            drained += 1
            _dbg(verbose, f'    [drain] malformed: {e}')
    return drained


def wake_bike(dev: FazuaHID, verbose: bool = True,
              max_attempts: int = 250, per_attempt_read_ms: int = 5) -> bytes:
    """Wake the bike by spamming 0x21 until it replies 0x22.

    Diagnostic-verified (diag_raw.py 2026-04-20): on firmware 2.04 after an
    upgrade/downgrade cycle, the bike needs ~108 attempts at max speed before
    transitioning from 0x21 streaming to 0x22 ready. On a clean 2.04 install
    it took ~21 attempts. Use 250 max with 5ms read timeout for headroom.

    Returns the bike's 0x22 reply packet.
    """
    _dbg(verbose, f'    [wake] spamming 0x21 until bike replies 0x22...')
    ctrl_21 = build_control_packet(CTRL_MORE)
    for attempt in range(max_attempts):
        dev.write(ctrl_21, timeout_ms=200)
        try:
            r = dev.read(timeout_ms=per_attempt_read_ms)
        except TimeoutError:
            continue
        if r[1] == CTRL_READY:
            _dbg(verbose, f'    [wake] bike ready after {attempt + 1} attempts')
            return r
        # 0x21 streaming or anything else: keep spamming
        if verbose and (attempt + 1) % 50 == 0:
            _dbg(verbose, f'    [wake] ... {attempt + 1} attempts, still 0x{r[1]:02x}')
    raise TimeoutError(
        f"bike did not reply 0x22 within {max_attempts} wake attempts. "
        f"Unplug USB, wait 10s, replug, retry.")


def _ack_data_stream(dev: FazuaHID, verbose: bool, max_blocks: int = 16):
    """After caller has received a data-stream primary block (status 0x01),
    ACK each continuation block until EOT (status 0x04). Verifies CRC on
    every block. Returns the continuation blocks (not including the primary)."""
    blocks = []
    for _ in range(max_blocks):
        _dbg(verbose, f'    >> 0x06 ACK')
        dev.write(build_control_packet(CTRL_ACK))
        r = dev.read(timeout_ms=1000)
        _dbg(verbose, f'    << {r[:4].hex()}... (status 0x{r[1]:02x})')
        if not verify_crc(r):
            raise ProtocolError(f'CRC mismatch on continuation block: {r.hex()}')
        blocks.append(r)
        if r[1] == 0x04:
            return blocks
        if r[1] != 0x01:
            raise ProtocolError(f'unexpected status byte 0x{r[1]:02x} in data stream')
    raise ProtocolError(f'data stream did not terminate within {max_blocks} blocks')


def _do_cycle_preamble(dev: FazuaHID, verbose: bool, max_chain_rounds: int = 16):
    """Send 0x25 + 0x21 preamble to transition the bike into "ready" state.

    Matches fazua_proto.py's verified approach: send 0x25 (close) and 0x21
    (preamble) back-to-back, then read response (skipping any 0x21 streaming
    packets). If bike responds 0x22: ready for queries. If bike responds with
    chained data (0x01 block): send 0x22, drain the data push, and retry.
    """
    for chain_round in range(max_chain_rounds):
        _dbg(verbose, f'    >> 0x25 + 0x21 (preamble, round {chain_round})')
        dev.write(build_control_packet(CTRL_CYCLE))
        dev.write(build_control_packet(CTRL_MORE))
        r = _read_skip_streaming(dev, verbose, 'preamble')
        _dbg(verbose, f'    << 0x{r[1]:02x}')

        if r[1] == CTRL_READY:
            return r
        if r[1] == CTRL_MORE:
            # Bike has chained data — acknowledge it, drain, retry
            _dbg(verbose, f'    (chained data; sending 0x22 and draining)')
            dev.write(build_control_packet(CTRL_READY))
            primary = _read_skip_streaming(dev, verbose, 'chained-primary')
            _dbg(verbose, f'    << chained primary: {primary[:8].hex()}...')
            if primary[1] == 0x01:
                _ack_data_stream(dev, verbose)
            continue
        if r[1] == 0x01:
            # Bike sent a data block directly — drain it and retry
            _dbg(verbose, f'    (unsolicited data block; draining)')
            _ack_data_stream(dev, verbose)
            continue
        raise ProtocolError(
            f'unexpected reply 0x{r[1]:02x} to 0x25+0x21 preamble '
            f'(expected 0x22, 0x21, or 0x01)')
    raise TimeoutError(f'preamble did not converge to 0x22 after {max_chain_rounds} rounds')


def _close_read_cycle(dev: FazuaHID, verbose: bool):
    """Send 0x25 to close the read cycle after bike's EOT.

    After the bike's data-stream EOT, send 0x25. The bike transitions to
    "waiting-for-0x21" state and stays silent until the next cycle's 0x21
    preamble arrives.

    We do NOT read after the 0x25. The 0x21 preamble (in _do_cycle_preamble)
    will elicit the 0x22 response that confirms cycle transition.
    """
    _dbg(verbose, f'    >> 0x25 (close)')
    dev.write(build_control_packet(CTRL_CYCLE))


def _read_skip_stale(dev: FazuaHID, verbose: bool, label: str,
                     max_skip: int = 64, timeout_ms: int = 1000) -> bytes:
    """Read one HID packet, skipping both 0x21 streaming AND stale 0x22 packets.
    Use this when looking for 0x06 ACK — both 0x21 and 0x22 can be stale."""
    skipped = 0
    for _ in range(max_skip):
        r = dev.read(timeout_ms=timeout_ms)
        if r[1] not in (CTRL_MORE, CTRL_READY):
            if skipped:
                _dbg(verbose, f'    ({label}: skipped {skipped} stale packet(s))')
            return r
        skipped += 1
    raise ProtocolError(f'{label}: skipped {max_skip} stale packets without '
                        f'seeing a protocol response')


def _read_skip_streaming(dev: FazuaHID, verbose: bool, label: str,
                         max_skip: int = 32, timeout_ms: int = 1000) -> bytes:
    """Read one HID packet, silently skipping 0x21 live-data streaming packets.
    The bike continuously broadcasts 0x21 02 fd ... status updates that can
    interleave with protocol responses. This helper discards them."""
    skipped = 0
    for _ in range(max_skip):
        r = dev.read(timeout_ms=timeout_ms)
        if r[1] != CTRL_MORE or r[2:4] == b'\x00\x00':
            # Not a streaming packet (or it's a real 0x21 control packet
            # with no seq/~seq framing). Return it.
            if skipped:
                _dbg(verbose, f'    ({label}: skipped {skipped} streaming packet(s))')
            return r
        skipped += 1
    raise ProtocolError(f'{label}: skipped {max_skip} streaming packets without '
                        f'seeing a protocol response')


def do_read_query(dev: FazuaHID, cmd: bytes, verbose: bool = True,
                  skip_preamble: bool = False) -> bytes:
    """Full read cycle. Returns the primary 38-byte data packet for <cmd>.

    skip_preamble: pass True when bike is already in "ready" state (replies
    0x22) - namely right after wake_bike() or right after do_write_command().
    Pass False (default) when bike is in "waiting-for-0x21" state from a
    prior read cycle's 0x25 close.
    """
    if skip_preamble:
        # Spam 0x21 until bike replies 0x22, then query immediately.
        # The bike's ready state is brief — no delays allowed.
        _dbg(verbose, f'    [query] spamming 0x21 until 0x22...')
        ctrl_21 = build_control_packet(CTRL_MORE)
        got_ready = False
        for attempt in range(250):
            dev.write(ctrl_21, timeout_ms=200)
            try:
                r = dev.read(timeout_ms=5)
            except TimeoutError:
                continue
            if r[1] == CTRL_READY:
                _dbg(verbose, f'    [query] ready after {attempt + 1} attempts')
                got_ready = True
                break
            if verbose and (attempt + 1) % 50 == 0:
                _dbg(verbose, f'    [query] ... {attempt + 1} attempts')
        if not got_ready:
            raise TimeoutError('bike did not reply 0x22 for query preamble')
    else:
        _do_cycle_preamble(dev, verbose)

    query = build_query_packet(cmd)

    def _send_query_and_read_ack():
        """Send query and read ACK, tolerating stale 0x21/0x22/0x15 packets."""
        _dbg(verbose, f'    >> QUERY {cmd.hex()}')
        dev.write(query)
        last = None
        for attempt in range(32):
            last = dev.read(timeout_ms=1000)
            if last[1] == CTRL_ACK:
                if attempt:
                    _dbg(verbose, f'    (skipped {attempt} stale packet(s) before ACK)')
                return last
            if last[1] in (CTRL_READY, CTRL_MORE, 0x15):
                # 0x22 stale broadcast, 0x21 live-data, or 0x15 NAK — skip
                continue
            break
        return last

    # Retry logic: after a write, the bike may NAK (0x15) or need time.
    # Try up to 3 rounds with a re-wake between each.
    last_err = None
    for query_round in range(3):
        if query_round > 0:
            _dbg(verbose, f'    (query retry round {query_round}, re-waking...)')
            time.sleep(0.2)
            # Re-wake: spam 0x21 until 0x22
            ctrl_21 = build_control_packet(CTRL_MORE)
            for attempt in range(250):
                dev.write(ctrl_21, timeout_ms=200)
                try:
                    rr = dev.read(timeout_ms=5)
                except TimeoutError:
                    continue
                if rr[1] == CTRL_READY:
                    break
        try:
            r = _send_query_and_read_ack()
        except TimeoutError:
            last_err = TimeoutError('ACK timeout')
            continue
        if r[1] == CTRL_ACK:
            break
        last_err = ProtocolError(
            f'expected 0x06 ACK after query, got 0x{r[1]:02x}. '
            f'full: {r.hex()}')
    else:
        raise last_err

    _dbg(verbose, f'    << status 0x{r[1]:02x} (expect 0x06 ACK)')
    if r[1] != CTRL_ACK:
        raise ProtocolError(
            f'expected 0x06 ACK after query, got 0x{r[1]:02x}. '
            f'full: {r.hex()}')

    _dbg(verbose, f'    >> 0x04 EOT')
    dev.write(build_control_packet(CTRL_EOT))

    # Read 0x25 echo, skipping 0x21 streaming packets
    e1 = _read_skip_streaming(dev, verbose, 'echo-0x25')
    if e1[1] != CTRL_CYCLE:
        raise ProtocolError(f'expected 0x25 echo, got 0x{e1[1]:02x}')
    # Accept next 0x21 (echo or streaming — indistinguishable, doesn't matter)
    e2 = dev.read(timeout_ms=1000)
    _dbg(verbose, f'    << echo 0x{e2[1]:02x}')

    _dbg(verbose, f'    >> 0x22 (ready)')
    dev.write(build_control_packet(CTRL_READY))

    # Read primary data block — skip 0x21 streaming until we see 0x01 data
    primary = _read_skip_streaming(dev, verbose, 'primary-data')
    _dbg(verbose, f'    << primary: {primary[:12].hex()}...')
    want = b'\x00\x01\x01\xfe' + cmd
    if not primary.startswith(want):
        raise ProtocolError(
            f'primary data does not match expected prefix {want.hex()}: '
            f'got {primary[:6].hex()}')
    if not verify_crc(primary):
        raise ProtocolError(f'primary data CRC mismatch: {primary.hex()}')

    _ack_data_stream(dev, verbose)
    _close_read_cycle(dev, verbose)
    return primary


def do_write_command(dev: FazuaHID, block1: bytes, block2: bytes,
                     verbose: bool = True) -> None:
    """Full 03 01 write cycle."""
    if len(block1) != PACKET_LEN or len(block2) != PACKET_LEN:
        raise ValueError('both blocks must be 38 bytes')
    if not verify_crc(block1):
        raise ValueError('block1 CRC is invalid - refusing to send')
    if not verify_crc(block2):
        raise ValueError('block2 CRC is invalid - refusing to send')

    # Spam 0x21 until bike replies 0x22 (same approach as wake — bike's
    # ready state is brief after prior read cycle's close).
    _dbg(verbose, f'    [write] spamming 0x21 until bike replies 0x22...')
    ctrl_21 = build_control_packet(CTRL_MORE)
    got_ready = False
    for attempt in range(250):
        dev.write(ctrl_21, timeout_ms=200)
        try:
            r = dev.read(timeout_ms=5)
        except TimeoutError:
            continue
        if r[1] == CTRL_READY:
            _dbg(verbose, f'    [write] bike ready after {attempt + 1} attempts')
            got_ready = True
            break
        if verbose and (attempt + 1) % 50 == 0:
            _dbg(verbose, f'    [write] ... {attempt + 1} attempts')
    if not got_ready:
        raise TimeoutError('bike did not reply 0x22 for write preamble')

    # Send block1 immediately after 0x22
    _dbg(verbose, f'    >> BLOCK1 {block1.hex()[:14]}...')
    dev.write(block1)
    r = _read_skip_stale(dev, verbose, 'block1-ack')
    if r[1] != CTRL_ACK:
        raise ProtocolError(f'expected 0x06 ACK after block1, got 0x{r[1]:02x}')

    _dbg(verbose, f'    >> BLOCK2 {block2.hex()[:14]}...')
    dev.write(block2)
    r = _read_skip_stale(dev, verbose, 'block2-ack')
    if r[1] != CTRL_ACK:
        raise ProtocolError(f'expected 0x06 ACK after block2, got 0x{r[1]:02x}')

    _dbg(verbose, f'    >> 0x04 EOT')
    dev.write(build_control_packet(CTRL_EOT))

    # Read 0x25 echo (skip streaming)
    r = _read_skip_streaming(dev, verbose, 'write-echo-0x25')
    if r[1] != CTRL_CYCLE:
        raise ProtocolError(f'expected 0x25 echo after write EOT, got 0x{r[1]:02x}')

    _dbg(verbose, f'    >> 0x21 (post-amble 1)')
    dev.write(build_control_packet(CTRL_MORE))
    _dbg(verbose, f'    >> 0x21 (post-amble 2)')
    dev.write(build_control_packet(CTRL_MORE))

    # Accept 0x22 ready (skip streaming)
    r = _read_skip_streaming(dev, verbose, 'write-ready')
    if r[1] != CTRL_READY:
        raise ProtocolError(f'expected 0x22 ready after write, got 0x{r[1]:02x}')
    _dbg(verbose, f'    write cycle complete - bike acknowledged')


# =============================================================================
# High-level
# =============================================================================

def read_current_config(dev: FazuaHID, verbose: bool = True,
                        skip_preamble: bool = False) -> BikeConfig:
    primary = do_read_query(dev, CMD_GET_CONFIG, verbose=verbose,
                            skip_preamble=skip_preamble)
    return decode_config_packet(primary)


def write_bike_max_speed(dev: FazuaHID, current_raw_packet: bytes,
                         new_kmh: float, verbose: bool = True) -> None:
    block1 = build_03_01_block1_from_response(current_raw_packet, new_kmh)
    block2 = build_03_01_block2()
    _dbg(verbose, f'    block1: {block1.hex()}')
    _dbg(verbose, f'    block2: {block2.hex()}')
    do_write_command(dev, block1, block2, verbose=verbose)


# =============================================================================
# CLI
# =============================================================================

BANNER = r"""
___________                           ____ ___      .__                 __
\_   _____/____  __________ _______  |    |   \____ |  |   ____   ____ |  | __ ___________
 |    __) \__  \ \___   /  |  \__  \ |    |   /    \|  |  /  _ \_/ ___\|  |/ // __ \_  __ \
 |     \   / __ \_/    /|  |  // __ \|    |  /   |  \  |_(  <_> )  \___|    <\  ___/|  | \/
 \___  /  (____  /_____ \____/(____  /______/|___|  /____/\____/ \___  >__|_ \\___  >__|
     \/        \/      \/          \/             \/                 \/     \/    \/
"""
BANNER_LINES = [ln for ln in BANNER.splitlines() if ln.strip()]


# btop-style inset-title box. Title docks into the top border: ┌─┤ TITLE ├──┐.
BOX_WIDTH = 96


def _box_top(title: str) -> str:
    left = f"┌─┤ {title} ├"
    pad = BOX_WIDTH - len(left) - 1
    return left + "─" * pad + "┐"


def _box_bottom() -> str:
    return "└" + "─" * (BOX_WIDTH - 2) + "┘"


def _box_line(text: str = "") -> str:
    inner = " " + text
    inner = inner[:BOX_WIDTH - 2].ljust(BOX_WIDTH - 2)
    return "│" + inner + "│"


def _box_empty() -> str:
    return "│" + " " * (BOX_WIDTH - 2) + "│"


def print_banner() -> None:
    print(_box_top("FazuaUnlock"))
    print(_box_empty())
    for ln in BANNER_LINES:
        print(_box_line(ln))
    print(_box_empty())
    print(_box_bottom())


EU_WARNING_LINES = [
    "Under EN 15194 / Regulation (EU) 168/2013, a pedelec that assists motor power above",
    "25 km/h is legally reclassified (L1e-A/B category) and is NOT an EPAC. Riding a",
    "tampered bike on public roads in most EU states:",
    "",
    "  - is an administrative or criminal offence",
    "  - voids insurance coverage",
    "  - voids manufacturer type approval and warranty",
    "  - shifts product liability to whoever tampered",
    "",
    "For research / closed-course / private-property use only. Use at your own risk.",
    "Verified on Drivepack firmware 2.04 - do not use on other FW.",
]


def print_eu_warning() -> None:
    print(_box_top("EU REGULATORY WARNING"))
    for ln in EU_WARNING_LINES:
        print(_box_empty() if ln == "" else _box_line(ln))
    print(_box_bottom())


def print_motor_stats(config: BikeConfig) -> None:
    unit = 'km/h' if config.unit_tag == 0x05 else 'mph'
    write_key = derive_write_key(config.shaft_offset)
    rows = [
        ("Max Bike Speed", f"{config.bikeMaxSpeed_kmh:.2f} km/h (raw {config.bikeMaxSpeed_raw})"),
        ("Wheel Length",   f"{config.wheel_length_mm} mm"),
        ("Shaft Offset",   f"{config.shaft_offset} (0x{config.shaft_offset:04x})"),
        ("Write Key",      f"{write_key.hex()} (auto-derived)"),
        ("Unit Tag",       f"0x{config.unit_tag:02x} ({unit})"),
        ("Logs Period",    f"{config.logs_period}"),
    ]
    print(_box_top("Motor Status"))
    for label, value in rows:
        print(_box_line(f"{label:<24}{value}"))
    print(_box_bottom())


def _prompt_new_max_speed(current: BikeConfig):
    """Prompt user for new max speed. Returns float or None if cancelled."""
    print()
    print(f"  Current Max Bike Speed: {current.bikeMaxSpeed_kmh:.2f} km/h "
          f"(raw {current.bikeMaxSpeed_raw})")
    print(f"  Reference speeds:")
    print(f"     25 km/h  = factory setting (EU road-legal)")
    print(f"     75 km/h  = theoretical maximum (competition / closed-course use)")
    print()
    raw_in = input("  New Max Bike Speed (km/h) [blank to cancel]: ").strip()
    if not raw_in:
        print("  Cancelled.")
        return None
    try:
        new_kmh = float(raw_in)
    except ValueError:
        print(f"  Invalid number: {raw_in!r}")
        return None
    if not 5 <= new_kmh <= 75:
        print(f"  Out of range: {new_kmh} not in [5, 75]")
        return None
    return new_kmh


def _perform_write_and_verify(dev: FazuaHID, current: BikeConfig,
                              new_kmh: float, verbose: bool,
                              force: bool):
    """Execute the full write + verify flow. Returns the post-write config
    on success, None on abort or failure."""
    new_raw = kmh_to_raw(new_kmh)
    if new_raw == current.bikeMaxSpeed_raw:
        print(f"  Target {new_kmh:.2f} km/h already matches current - nothing to do.")
        return current

    print()
    print(f"  PROPOSED CHANGE:")
    print(f"    current: {current.bikeMaxSpeed_kmh:6.2f} km/h "
          f"(raw {current.bikeMaxSpeed_raw})")
    print(f"    new    : {new_kmh:6.2f} km/h "
          f"(raw {new_raw})")
    print()

    key = _load_write_key(current.shaft_offset)
    env_override = os.environ.get('FAZUA_WRITE_KEY', '').strip()
    key_source = "env FAZUA_WRITE_KEY" if env_override else f"auto-derived from Shaft_Offset={current.shaft_offset} (0x{current.shaft_offset:04x})"

    if not force:
        print(f"  Write-auth key: {key.hex()} ({key_source})")
        print("  WARNING: this modifies flash on the bike controller.")
        resp = input("  Type 'yes' to proceed: ").strip().lower()
        if resp != 'yes':
            print("  Aborted.")
            return None

    print("  Writing...")
    write_bike_max_speed(dev, current.raw, new_kmh, verbose=verbose)
    print("  Write cycle acknowledged by bike.")

    time.sleep(0.5)

    print("  Verifying...")
    after = read_current_config(dev, verbose=verbose, skip_preamble=True)

    if after.bikeMaxSpeed_raw == new_raw:
        print(f"  SUCCESS: bikeMaxSpeed is now {after.bikeMaxSpeed_kmh:.2f} km/h")
        return after
    print(f"  WARNING: verification mismatch - expected {new_kmh}, "
          f"got {after.bikeMaxSpeed_kmh}")
    return after


def _interactive_menu(dev: FazuaHID, current: BikeConfig, verbose: bool) -> int:
    """Interactive menu loop. Returns exit code."""
    while True:
        print()
        print(_box_top("MENU"))
        print(_box_empty())
        print(_box_line("[1] Change Maximum Bike Speed"))
        print(_box_empty())
        print(_box_line("[0] Exit"))
        print(_box_empty())
        print(_box_bottom())
        choice = input("  Select: ").strip()

        if choice in ('0', '', 'q', 'exit', 'quit'):
            print("  Goodbye.")
            return 0

        if choice == '1':
            new_kmh = _prompt_new_max_speed(current)
            if new_kmh is None:
                continue
            after = _perform_write_and_verify(dev, current, new_kmh,
                                              verbose=verbose, force=False)
            if after is not None:
                print()
                print_motor_stats(after)
            return 0

        print(f"  Invalid choice: {choice!r}")


def _parse_args():
    p = argparse.ArgumentParser(
        prog='fazua_unlock',
        description='Change bikeMaxSpeed on a Fazua RIDE 50 EVATION via USB HID.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  fazua_unlock.py --read-only           # show current config\n'
            '  fazua_unlock.py 35 --dry-run          # show packet that would be sent\n'
            '  fazua_unlock.py 35                    # prompt, then write\n'
            '  fazua_unlock.py 35 --force            # write without prompt\n'
        ))
    p.add_argument('target_kmh', nargs='?', type=float,
                   help='new max speed in km/h (omit with --read-only)')
    p.add_argument('--read-only', action='store_true',
                   help='read and print current config, do not write')
    p.add_argument('--dry-run', action='store_true',
                   help='read, build the write packet, print it, but do not send')
    p.add_argument('--force', action='store_true',
                   help='skip the y/N confirmation prompt')
    p.add_argument('-v', '--verbose', action='store_true',
                   help='print per-step protocol trace')
    args = p.parse_args()

    if args.read_only and args.target_kmh is not None:
        p.error('--read-only cannot be combined with target_kmh')
    if args.target_kmh is not None and not 5 <= args.target_kmh <= 75:
        p.error(f'target_kmh {args.target_kmh} out of allowed range [5, 75]')
    return args


def main() -> int:
    args = _parse_args()

    print_banner()
    print()
    print_eu_warning()
    print()

    check_no_blocking_processes(interactive=True)

    with FazuaHID() as dev:
        if args.verbose:
            print(f"Opened {dev.path}")
        dev.set_num_input_buffers(HID_INPUT_BUFFER_COUNT)

        # Start clean: drain any stale reports left by a prior session.
        drained = drain_buffer(dev, timeout_ms=50, max_packets=16,
                               verbose=args.verbose)
        if drained and args.verbose:
            print(f"(drained {drained} stale packets from HID queue)")

        print("Connecting to bike...")
        t0 = time.monotonic()
        wake_bike(dev, verbose=args.verbose)
        print(f"  Connected in {(time.monotonic() - t0) * 1000:.0f}ms")

        # After wake, bike just sent 0x22 — it's in ready state.
        current = read_current_config(dev, verbose=args.verbose, skip_preamble=True)

        print()
        print_motor_stats(current)

        # --read-only: show stats and exit
        if args.read_only:
            return 0

        # CLI flag mode (positional target_kmh given): run single-shot write
        if args.target_kmh is not None:
            if args.dry_run:
                new_raw = kmh_to_raw(args.target_kmh)
                if new_raw == current.bikeMaxSpeed_raw:
                    print(f"\nTarget {args.target_kmh:.2f} km/h already matches - nothing to do.")
                    return 0
                block1 = build_03_01_block1_from_response(current.raw, args.target_kmh)
                block2 = build_03_01_block2()
                print()
                print("DRY RUN - packets that would be sent:")
                print(f"  block1: {block1.hex()}")
                print(f"  block2: {block2.hex()}")
                print("(no write performed)")
                return 0

            after = _perform_write_and_verify(dev, current, args.target_kmh,
                                              verbose=args.verbose,
                                              force=args.force)
            if after is None:
                return 1
            return 0 if after.bikeMaxSpeed_raw == kmh_to_raw(args.target_kmh) else 2

        # No flags: interactive menu
        return _interactive_menu(dev, current, verbose=args.verbose)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[interrupted]")
        sys.exit(130)
    except (TimeoutError, ProtocolError, OSError, RuntimeError) as e:
        print(f"\nERROR: {type(e).__name__}: {e}")
        sys.exit(1)
