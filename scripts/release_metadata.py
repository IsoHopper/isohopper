# SPDX-License-Identifier: GPL-3.0-or-later
"""Release descriptions derived from the checked-out native implementation."""
from pathlib import Path
import re

REPOSITORY = 'IsoHopper/isohopper'


def capabilities(root, platform):
    source = (Path(root) / 'studio/src-tauri/src/main.rs').read_text(encoding='utf-8')
    matches = re.findall(r'^const PHYSICAL_PREPARATION_ENABLED: bool = (true|false);$', source, re.M)
    if len(matches) != 1:
        raise ValueError('Cannot establish the native physical preparation gate')
    windows = platform == 'windows-x64'
    return {
        'native_file_import': True,
        'read_only_device_inventory': True,
        'preparation_staging': windows,
        'physical_preparation': windows and matches[0] == 'true',
        'engine_payloads_bundled': False,
    }


def scope_description(value):
    if value['physical_preparation']:
        return ('Windows USB preparation is experimental; it requires the installed helper, '
                'a separately supplied pinned engine archive and explicit device confirmation.\n')
    if value['preparation_staging']:
        return 'Windows staging is experimental. Physical disk writes are disabled.\n'
    return 'Inspection and local image hashing only. Physical disk writes are disabled.\n'
