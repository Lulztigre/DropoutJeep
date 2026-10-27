"""DNS provider implementations for wildcard record management.

Each provider exposes ``create_record`` and ``delete_record``. Only wildcard A
records are needed for the multi-domain feature: one ``*.base.example.com``
record pointing at the proxy server IP serves all per-recipient subdomains.
"""

import json
import logging
import subprocess
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger(__name__)


try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


class DNSProvider(ABC):
    """Base class for DNS providers."""

    @abstractmethod
    def create_record(self, name: str, record_type: str, value: str) -> bool:
        """Create a DNS record. Return True on success."""
        pass

    @abstractmethod
    def delete_record(self, name: str, record_type: str, value: str) -> bool:
        """Delete a DNS record. Return True on success."""
        pass


class NoopDNSProvider(DNSProvider):
    """Provider that does nothing. Used when DNS is managed externally."""

    def create_record(self, name: str, record_type: str, value: str) -> bool:
        logger.info("NoopDNS: skipped creating %s %s -> %s", name, record_type, value)
        return True

    def delete_record(self, name: str, record_type: str, value: str) -> bool:
        logger.info("NoopDNS: skipped deleting %s %s -> %s", name, record_type, value)
        return True


class ManualDNSProvider(DNSProvider):
    """Provider that only logs the required record. Useful for testing."""

    def __init__(self, credentials: dict | None = None):
        self.credentials = credentials or {}

    def create_record(self, name: str, record_type: str, value: str) -> bool:
        logger.warning(
            "MANUAL DNS: create %s %s -> %s (add this record in your DNS panel)",
            name, record_type, value
        )
        return True

    def delete_record(self, name: str, record_type: str, value: str) -> bool:
        logger.warning(
            "MANUAL DNS: delete %s %s -> %s (remove this record from your DNS panel)",
            name, record_type, value
        )
        return True


class CloudflareDNSProvider(DNSProvider):
    """Cloudflare DNS provider using the v4 API."""

    API_BASE = "https://api.cloudflare.com/client/v4"

    def __init__(self, api_token: str, zone_id: str):
        self.api_token = api_token
        self.zone_id = zone_id

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json",
        }

    def _request(self, method: str, path: str, payload: dict | None = None) -> Any:
        if requests is None:
            raise RuntimeError("requests library is required for Cloudflare DNS")
        url = f"{self.API_BASE}{path}"
        kwargs = {"headers": self._headers()}
        if payload is not None:
            kwargs["json"] = payload
        resp = requests.request(method, url, **kwargs)
        resp.raise_for_status()
        return resp.json().get("result")

    def create_record(self, name: str, record_type: str, value: str) -> bool:
        try:
            self._request(
                "POST",
                f"/zones/{self.zone_id}/dns_records",
                {"type": record_type, "name": name, "content": value, "ttl": 120},
            )
            logger.info("Cloudflare: created %s %s -> %s", name, record_type, value)
            return True
        except Exception as exc:
            logger.exception("Cloudflare create_record failed: %s", exc)
            return False

    def delete_record(self, name: str, record_type: str, value: str) -> bool:
        try:
            records = self._request(
                "GET",
                f"/zones/{self.zone_id}/dns_records",
                {"type": record_type, "name": name},
            )
            for record in records or []:
                if record.get("content") == value:
                    self._request(
                        "DELETE",
                        f"/zones/{self.zone_id}/dns_records/{record['id']}",
                    )
                    logger.info("Cloudflare: deleted %s %s -> %s", name, record_type, value)
            return True
        except Exception as exc:
            logger.exception("Cloudflare delete_record failed: %s", exc)
            return False


class Route53DNSProvider(DNSProvider):
    """AWS Route53 provider using the AWS CLI."""

    def __init__(self, credentials: dict):
        self.zone_id = credentials.get("zone_id")
        self.profile = credentials.get("profile")

    def _base_cmd(self) -> list[str]:
        cmd = ["aws", "route53", "change-resource-record-sets"]
        if self.profile:
            cmd.extend(["--profile", self.profile])
        return cmd

    def _change_record(self, action: str, name: str, record_type: str, value: str) -> bool:
        change_batch = {
            "Changes": [
                {
                    "Action": action,
                    "ResourceRecordSet": {
                        "Name": name,
                        "Type": record_type,
                        "TTL": 300,
                        "ResourceRecords": [{"Value": value}],
                    },
                }
            ]
        }
        args = [
            *self._base_cmd(),
            "--hosted-zone-id",
            self.zone_id,
            "--change-batch",
            json.dumps(change_batch),
        ]
        try:
            subprocess.run(args, check=True, capture_output=True, text=True)
            logger.info("Route53: %s %s %s -> %s", action, name, record_type, value)
            return True
        except subprocess.CalledProcessError as exc:
            logger.error("Route53 %s failed: %s", action, exc.stderr)
            return False

    def create_record(self, name: str, record_type: str, value: str) -> bool:
        return self._change_record("CREATE", name, record_type, value)

    def delete_record(self, name: str, record_type: str, value: str) -> bool:
        return self._change_record("DELETE", name, record_type, value)


class DigitalOceanDNSProvider(DNSProvider):
    """DigitalOcean DNS provider using the v2 API."""

    API_BASE = "https://api.digitalocean.com/v2/domains"

    def __init__(self, api_token: str, domain: str):
        self.api_token = api_token
        self.domain = domain

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_token}", "Content-Type": "application/json"}

    def _request(self, method: str, path: str, payload: dict | None = None) -> Any:
        if requests is None:
            raise RuntimeError("requests library is required for DigitalOcean DNS")
        url = f"{self.API_BASE}/{self.domain}{path}"
        kwargs = {"headers": self._headers()}
        if payload is not None:
            kwargs["json"] = payload
        resp = requests.request(method, url, **kwargs)
        resp.raise_for_status()
        return resp.json()

    def create_record(self, name: str, record_type: str, value: str) -> bool:
        try:
            self._request(
                "POST",
                "/records",
                {"type": record_type, "name": name, "data": value, "ttl": 300},
            )
            logger.info("DigitalOcean: created %s %s -> %s", name, record_type, value)
            return True
        except Exception as exc:
            logger.exception("DigitalOcean create_record failed: %s", exc)
            return False

    def delete_record(self, name: str, record_type: str, value: str) -> bool:
        try:
            records = self._request("GET", "/records").get("domain_records", [])
            for record in records:
                if record.get("name") == name and record.get("type") == record_type:
                    self._request("DELETE", f"/records/{record['id']}")
                    logger.info("DigitalOcean: deleted %s %s", name, record_type)
                    return True
            return True
        except Exception as exc:
            logger.exception("DigitalOcean delete_record failed: %s", exc)
            return False


def get_dns_provider(provider_name: str, credentials: dict | None) -> DNSProvider:
    """Factory that returns a DNS provider instance by name."""
    credentials = credentials or {}
    name = (provider_name or "none").lower()
    if name == "cloudflare":
        return CloudflareDNSProvider(
            credentials.get("api_token", ""),
            credentials.get("zone_id", ""),
        )
    if name == "route53":
        return Route53DNSProvider(credentials)
    if name == "digitalocean":
        return DigitalOceanDNSProvider(
            credentials.get("api_token", ""),
            credentials.get("domain", ""),
        )
    if name == "manual":
        return ManualDNSProvider(credentials)
    return NoopDNSProvider()
