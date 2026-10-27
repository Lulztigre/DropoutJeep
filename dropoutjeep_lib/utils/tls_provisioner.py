"""TLS provisioning helpers for multi-domain campaigns.

Supports two strategies:

- ``caddy``: rely on Caddy on-demand TLS. DropoutJeep only needs to expose an
  ``/internal/caddy-ask`` endpoint that authorizes domains from the
  ``ProxyDomain`` table. Caddy fetches and renews certificates automatically.

- ``certbot``: obtain a wildcard certificate via Certbot DNS-01 and store the
  resulting cert/key paths on disk. Requires ``certbot`` and the matching DNS
  plugin to be installed on the server.
"""

import logging
import subprocess
from pathlib import Path
from typing import Any

from dropoutjeep_lib import db
from dropoutjeep_lib.models import ProxyDomain

logger = logging.getLogger(__name__)


def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            return False, result.stderr.strip() or result.stdout.strip()
        return True, result.stdout.strip()
    except Exception as exc:
        return False, str(exc)


def _certbot_dns_plugin(provider: str) -> str:
    mapping = {
        "cloudflare": "certbot-dns-cloudflare",
        "route53": "certbot-dns-route53",
        "digitalocean": "certbot-dns-digitalocean",
    }
    return mapping.get(provider, "")


def _write_certbot_credentials(provider: str, credentials: dict, work_dir: Path) -> Path | None:
    if provider == "cloudflare":
        path = work_dir / "cloudflare.ini"
        path.write_text(
            f"dns_cloudflare_api_token = {credentials.get('api_token', '')}\n",
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path
    if provider == "digitalocean":
        path = work_dir / "digitalocean.ini"
        path.write_text(
            f"dns_digitalocean_token = {credentials.get('api_token', '')}\n",
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path
    return None


def _certbot_args(proxy_domain: ProxyDomain, work_dir: Path) -> list[str] | None:
    provider = proxy_domain.dns_provider
    credentials = proxy_domain.get_dns_credentials() or {}
    plugin = _certbot_dns_plugin(provider)
    if not plugin:
        logger.error("No certbot DNS plugin mapped for provider %s", provider)
        return None

    args = [
        "certbot", "certonly", "--non-interactive", "--agree-tos",
        "--server", "https://acme-v02.api.letsencrypt.org/directory",
        "--email", proxy_domain.acme_email or "admin@example.com",
        "--dns", provider,
        "-d", f"*.{proxy_domain.base_domain}",
        "-d", proxy_domain.base_domain,
        "--config-dir", str(work_dir / "certbot"),
        "--work-dir", str(work_dir / "certbot-work"),
        "--logs-dir", str(work_dir / "certbot-logs"),
    ]

    creds_path = _write_certbot_credentials(provider, credentials, work_dir)
    if creds_path:
        args.extend(["--dns-", f"{provider}-credentials", str(creds_path)])

    return args


def provision_tls(proxy_domain: ProxyDomain, work_dir: Path | str | None = None) -> bool:
    """Provision TLS for a wildcard ProxyDomain and persist the result."""
    from datetime import datetime

    if not proxy_domain.is_wildcard:
        return True

    proxy_domain.last_provisioned_at = datetime.utcnow()
    proxy_domain.provision_error = None

    provider = (proxy_domain.tls_provider or "none").lower()
    if provider == "none":
        proxy_domain.tls_ready = False
        db.session.commit()
        return True

    if provider == "caddy":
        # Caddy handles TLS on-demand; we only authorize the domain.
        proxy_domain.tls_ready = True
        db.session.commit()
        logger.info("Caddy on-demand TLS enabled for %s", proxy_domain.base_domain)
        return True

    if provider == "certbot":
        work_dir = Path(work_dir or "instance/tls")
        work_dir.mkdir(parents=True, exist_ok=True)
        args = _certbot_args(proxy_domain, work_dir)
        if not args:
            proxy_domain.provision_error = "No certbot DNS plugin mapped"
            proxy_domain.tls_ready = False
            db.session.commit()
            return False

        ok, output = _run(args)
        if not ok:
            proxy_domain.provision_error = output[:2048]
            proxy_domain.tls_ready = False
            db.session.commit()
            return False

        base = proxy_domain.base_domain
        cert_dir = work_dir / "certbot" / "live" / base
        proxy_domain.cert_path = str(cert_dir / "fullchain.pem")
        proxy_domain.key_path = str(cert_dir / "privkey.pem")
        proxy_domain.tls_ready = cert_dir.exists()
        db.session.commit()
        logger.info("Certbot obtained wildcard cert for %s", base)
        return proxy_domain.tls_ready

    proxy_domain.provision_error = f"Unknown TLS provider: {provider}"
    proxy_domain.tls_ready = False
    db.session.commit()
    return False


def is_domain_authorized(domain: str) -> bool:
    """Return True when ``domain`` is allowed for Caddy on-demand TLS."""
    pd = ProxyDomain.query.filter_by(is_active=True).first()
    if not pd:
        return False

    # Exact match
    if pd.domain == domain:
        return True

    # Wildcard match: victim123.base.example.com matches *.base.example.com
    if pd.is_wildcard and pd.base_domain:
        suffix = "." + pd.base_domain
        if domain.endswith(suffix):
            return True

    return False
