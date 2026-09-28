#!/usr/bin/env python3
"""Fetch the latest Forge Core snapshot once per release; local builds use --source."""
import argparse
import io
from pathlib import Path
import urllib.request
import zipfile

URL = 'https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
with urllib.request.urlopen(URL, timeout=120) as response:
    archive = response.read(50 * 1024 * 1024 + 1)
if len(archive) > 50 * 1024 * 1024:
    raise SystemExit('Forge archive exceeded the release input limit')
with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
    names = [name for name in zipped.namelist() if Path(name).name == 'yara-rules-core.yar']
    if len(names) != 1:
        raise SystemExit('Expected exactly one Forge Core source file')
    source = zipped.read(names[0])
if b'YARA-Forge' not in source or b'Creation Date:' not in source:
    raise SystemExit('Unexpected Forge source format')
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_bytes(source)
print('Refreshed Forge Core:', args.output)
