"""
AERoot POC module
"""

import subprocess

SNAPSHOT_NAME = "aeroot"

def _exec(cmd):
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

def save_snapshot(name=SNAPSHOT_NAME):
    _exec(["adb", "emu", f"avd snapshot save {name}"])

def load_snapshot(name=SNAPSHOT_NAME):
    _exec(["adb", "emu", f"avd snapshot load {name}"])

def delete_snapshot(name=SNAPSHOT_NAME):
    _exec(["adb", "emu", f"avd snapshot delete {name}"])

def refresh_gdbstub():
    save_snapshot()
    load_snapshot()
    delete_snapshot()
