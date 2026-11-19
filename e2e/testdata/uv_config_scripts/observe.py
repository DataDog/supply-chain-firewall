"""Observe a real SCFW process without wrapping or replacing the manager."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

input_path, state_path, temporary, *argv = sys.argv[1:]
snapshots = {}
with open(input_path, "rb") as source:
    process = subprocess.Popen(argv, stdin=source)
    while process.poll() is None:
        for path in Path(temporary).glob("scfw-proxy-*/uv.toml"):
            try:
                content = path.read_text()
                if content:
                    snapshots[str(path)] = content
            except FileNotFoundError:
                pass
        time.sleep(0.001)
    state = {
        "argv": argv,
        "exit": process.returncode,
        "stdin_offset": source.tell(),
        "stdin_size": os.fstat(source.fileno()).st_size,
        "merged_configs": snapshots,
    }
Path(state_path).write_text(json.dumps(state, indent=2) + "\n")
sys.exit(process.returncode if process.returncode >= 0 else 128 - process.returncode)
