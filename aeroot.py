#!/usr/bin/env python3

""" AERoot (Android Emulator Rooting system) """

import argparse
from enum import auto, IntEnum
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import sys

try:
    import colorama
    from colorama import Fore, Style
except ModuleNotFoundError:
    pass

from pygdbmi.gdbcontroller import GdbController
from pygdbmi.constants import GdbTimeoutError
import ppadb
from ppadb.client import Client as AdbClient


logger = logging.getLogger(__name__)

VERSION = "0.2"
LOGO = r"""    _           _         _   _
 __|_|___      ( \       ( ) ( )
(  _____/       \ \     _| |_| |
| (|_|__    _____\ \   (_   _   _)
(_____  )  (_____)) )   _| (_) |
/\_|_|) |        / /   (_   _   _)
\_______)       / /      | | | |
   |_|         (_/       (_) (_)
"""

EXIT_ERR = 1

CAPABILITIES_OFFSETS = [0x30, 0x34, 0x38, 0x3c, 0x40, 0x44]
IDS_OFFSETS = [0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24]

# Logging functions

def colorize(msg: str, color: str) -> str:
    return "{}{}{}".format(color, msg, Style.RESET_ALL)


def debug(msg: str):
    try:
        prefix = " [{}]".format(colorize("-", Fore.CYAN))
    except NameError:
        prefix = " [-]"

    logger.debug("%s %s", prefix, msg)


def error(msg: str, do_exit: bool = False):
    try:
        prefix = "[{}]".format(colorize("!", Fore.RED))
    except NameError:
        prefix = "[!]"

    logger.error("%s %s", prefix, msg)

    if do_exit:
        sys.exit(EXIT_ERR)


def info(msg: str):
    try:
        prefix = "[{}]".format(colorize("+", Fore.GREEN))
    except NameError:
        prefix = "[+]"

    logger.info("%s %s", prefix, msg)


def title(msg: str):
    try:
        logger.info(colorize(msg, Fore.BLUE))
    except NameError:
        logger.info(msg)


class Mode(IntEnum):
    PID = auto()
    NAME = auto()


class GdbHelper:

    _WRITE_METHODS = {
        1: "write_byte",
        4: "write_dword",
        8: "write_qword"
    }

    def __init__(self, arch: str = "x86", timeout: int = 180):
        self.gdb = GdbController(time_to_check_for_additional_output_sec=timeout)

        if arch == "x86_64":
            self.gdb.write("set arch i386:x86-64:intel")

    def stop(self):
        self.gdb.exit()

    def start(self):
        self.gdb.write("target remote :1234")

    def write(self, address: int, value: int, size: int=1):
        getattr(self, GdbHelper._WRITE_METHODS.get(size, "write_byte"))(address, value)

    def write_byte(self, address: int, value: int):
        self.gdb.write("set *(unsigned char*) (%#x) = %#x" % (address, value))

    def write_dword(self, address: int, value: int):
        self.gdb.write("set *(unsigned int*) (%#x) = %#x" % (address, value))

    def write_qword(self, address: int, value: int):
        self.gdb.write("set *(unsigned long*) (%#x) = %#x" % (address, value))

    def read_dword(self, address: int) -> int:
        response = self.gdb.write("x/wx %#x" % address)[1]["payload"]

        return int(response.split("\\t")[1].replace("\\n", ""), 16)

    def read_addr(self, address: int) -> int:
        response = self.gdb.write("x/a %#x" % address)[1]["payload"]

        return int(response.split("\\t")[1].replace("\\n", ""), 16)

    def read_str(self, address: int) -> str:
        response = self.gdb.write("x/s %#x" % address)[1]["payload"]

        return response.split("\\t")[1].replace("\\n", "").replace("\\\"", "")

    def read_ip(self) -> int:
        response = self.gdb.write("p/x $pc")[1]["payload"]

        return int(response.split(" = ")[1].replace("\\n", ""), 16)

    def find(self, query: str) -> List[int]:
        addresses = []
        response = self.gdb.write("find %s" % query, timeout_sec=180)

        for subset in response:
            payload = subset.get("payload")

            if payload is not None and payload.startswith("0x"):
                addresses.append(int(payload.replace("\\n", ""), 16))

        return addresses


class Process:
    def __init__(self, name: Optional[str] = None, pid: Optional[int] = None):
        self.name, self.pid = name, pid

    def match(self, gdb: GdbHelper, avd: Dict[str, Any], address: int) -> bool:
        if self.pid is not None:
            pid = gdb.read_dword(address + avd.get("offset_to_pid"))
            debug("Looking at {} - [{}]".format(hex(address), pid))

            return self.pid == pid

        if self.name is not None:
            name = gdb.read_str(address + avd.get("offset_to_comm"))
            debug("Looking at {} - [{}]".format(hex(address), name))

            return self.name == name

        return False

    def is_running(self, device: ppadb.device.Device, avd: Dict[str, Any]) -> bool:
        if self.pid is not None:
            return str(self.pid) in device.shell(avd.get("ps_pid_cmd", "ps")).split()

        if self.name is not None:
            return self.name in device.shell(avd.get("ps_name_cmd", "ps")).split()

        return False

    def __str__(self) -> str:
        if self.pid is not None:
            return "[{}]".format(self.pid)

        if self.name is not None:
            return "[{}]".format(self.name)

        return ""


def load_avds(path: str) -> Dict[str, dict]:
    debug("Loading {} ...".format(path))

    try:
        with open(path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        error("Unable to load config file.", True)


def get_avd(avds: Dict[str, dict], device: ppadb.device.Device) -> Optional[Dict[str, Any]]:
    result = device.shell("uname -rm").strip()
    return avds.get(result)


# Specific for android 10
def find_init(gdb: GdbHelper, avd: Dict[str, Any]):
    mem_init_ptr = gdb.read_addr(avd.get("kernel_ptr")) + avd.get("offset_to_init_ptr")
    avd["init_addr"] = gdb.read_addr(mem_init_ptr) - avd.get("offset_to_tasks")


def find_task_struct(gdb: GdbHelper, avd: Dict[str, Any], process: Process) -> Optional[int]:
    return next(filter(lambda x: process.match(gdb, avd, x), get_task_structs(gdb, avd)), None)


def get_task_structs(gdb: GdbHelper, avd: Dict[str, Any]) -> int:
    if "offset_to_init_ptr" in avd:
        find_init(gdb, avd)

    if "init_ptr" in avd:
        debug("Entering Android 7.x workaround")
        avd["init_addr"] = gdb.read_addr(avd.get("init_ptr"))

    debug("Init task_struct found at: {}".format(hex(avd.get("init_addr"))))

    current_prev_ptr = avd.get("init_addr") + avd.get("offset_to_tasks") + avd.get("ptr_size")
    current_task_struct = gdb.read_addr(current_prev_ptr) - avd.get("offset_to_tasks")

    while current_task_struct != avd.get("init_addr"):
        yield current_task_struct

        current_prev_ptr = current_task_struct + avd.get("offset_to_tasks") + avd.get("ptr_size")
        current_task_struct = gdb.read_addr(current_prev_ptr) - avd.get("offset_to_tasks")


def overwrite_credentials(gdb: GdbHelper, avd: Dict[str, Any], address: int):
    process_creds_addr = gdb.read_addr(address + avd.get("offset_to_creds"))

    set_full_capabilities(gdb, process_creds_addr)
    set_root_ids(gdb, process_creds_addr)


def set_full_capabilities(gdb: GdbHelper, address: int):
    debug("Overwriting Capabilities.")

    for offset in CAPABILITIES_OFFSETS:
        gdb.write_dword(address + offset, 0xffffffff)


def set_root_ids(gdb: GdbHelper, address: int):
    debug("Overwriting IDs.")

    for offset in IDS_OFFSETS:
        gdb.write_dword(address + offset, 0x00000000)


def disable_selinux(gdb: GdbHelper, avd: Dict[str, Any]):
    if "selinux_addr" in avd:
        selinux_address = avd.get("selinux_addr")
    else:
        selinux_address = gdb.read_addr(avd.get("kernel_ptr")) + avd.get("selinux_offset")

    debug("SELinux mode found at {}".format(hex(selinux_address)))

    gdb.write(selinux_address, 0, avd.get("enforce_size", 1))

def show_process_info(gdb: GdbHelper, avd: Dict[str, Any], process_addr: int):
    info("Process found. Showing memory information.")

    print("\n{:<20}{:<40}{:<20}".format("Field/Data", "Value", "Address"))
    print("-" * 80)

    print("{:<20}{:<40}{:<20}".format("task_struct", "-", hex(process_addr)))

    pid_addr = process_addr + avd.get("offset_to_pid")
    pid = gdb.read_dword(pid_addr)

    print("{:<20}{:<40}{:<20}".format("pid", pid, hex(pid_addr)))

    comm_addr = process_addr + avd.get("offset_to_comm")
    comm = gdb.read_str(comm_addr)

    print("{:<20}{:<40}{:<20}".format("comm", comm, hex(comm_addr)))

    parent_ptr_addr = process_addr + avd.get("offset_to_parent")
    parent_ptr = gdb.read_addr(parent_ptr_addr)
    parent_comm = gdb.read_str(parent_ptr + avd.get("offset_to_comm"))
    parent_value = "{} ({})".format(hex(parent_ptr), parent_comm)

    print("{:<20}{:<40}{:<20}".format("parent", parent_value, hex(parent_ptr_addr)))

    next_ptr_addr = process_addr + avd.get("offset_to_tasks")
    next_ptr = gdb.read_addr(next_ptr_addr)
    next_comm = gdb.read_str(next_ptr + avd.get("offset_to_comm") - avd.get("offset_to_tasks"))
    next_value = "{} ({})".format(hex(next_ptr), next_comm)

    print("{:<20}{:<40}{:<20}".format("next", next_value, hex(next_ptr_addr)))

    prev_ptr_addr = next_ptr_addr + avd.get("ptr_size")
    prev_ptr = gdb.read_addr(prev_ptr_addr)
    prev_comm = gdb.read_str(prev_ptr + avd.get("offset_to_comm") - avd.get("offset_to_tasks"))
    prev_value = "{} ({})".format(hex(prev_ptr), prev_comm)

    print("{:<20}{:<40}{:<20}".format("prev", prev_value, hex(prev_ptr_addr)))

    creds_ptr_addr = process_addr + avd.get("offset_to_creds")
    creds_ptr = gdb.read_addr(creds_ptr_addr)

    print("{:<20}{:<40}{:<20}".format("credentials", "-", hex(creds_ptr)))

    print("{:<20}{:<40}{:<20}".format(" > uid", hex(gdb.read_dword(creds_ptr + 0x04)), ""))
    print("{:<20}{:<40}{:<20}".format(" > gid", hex(gdb.read_dword(creds_ptr + 0x08)), ""))
    print("{:<20}{:<40}{:<20}".format(" > suid", hex(gdb.read_dword(creds_ptr + 0x0c)), ""))
    print("{:<20}{:<40}{:<20}".format(" > sgid", hex(gdb.read_dword(creds_ptr + 0x10)), ""))
    print("{:<20}{:<40}{:<20}".format(" > euid", hex(gdb.read_dword(creds_ptr + 0x14)), ""))
    print("{:<20}{:<40}{:<20}".format(" > egid", hex(gdb.read_dword(creds_ptr + 0x18)), ""))
    print("{:<20}{:<40}{:<20}".format(" > fsuid", hex(gdb.read_dword(creds_ptr + 0x1c)), ""))
    print("{:<20}{:<40}{:<20}".format(" > fsgid", hex(gdb.read_dword(creds_ptr + 0x20)), ""))
    print("{:<20}{:<40}{:<20}".format(" > securebits", hex(gdb.read_dword(creds_ptr + 0x24)), ""))

    print("{:<20}{:<40}{:<20}".format("capabilities", "-", hex(creds_ptr + 0x30)))
    print("{:<20}{:<40}{:<20}".format("", hex(gdb.read_dword(creds_ptr + 0x30)),""))
    print("{:<20}{:<40}{:<20}".format("", hex(gdb.read_dword(creds_ptr + 0x34)), ""))
    print("{:<20}{:<40}{:<20}".format("", hex(gdb.read_dword(creds_ptr + 0x38)), ""))
    print("{:<20}{:<40}{:<20}".format("", hex(gdb.read_dword(creds_ptr + 0x3c)), ""))
    print("{:<20}{:<40}{:<20}".format("", hex(gdb.read_dword(creds_ptr + 0x40)), ""))
    print("{:<20}{:<40}{:<20}".format("", hex(gdb.read_dword(creds_ptr + 0x44)), ""))

    print("\n")

def handle_cmd_line() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AERoot (Android Emulator ROOTing system) v. {}".format(VERSION)
    )
    parser.add_argument(
        "--config_file",
        "-c",
        type=str,
        default=str(Path(Path.cwd(), "config.json"))
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--verbose", "-v", action="store_true", help="show debug level messages")
    group.add_argument("--quiet", "-q", action="store_true", help="quiet output")
    parser.add_argument("--show", "-s", action="store_true", help="show information about the target process (don't modify the device memory)")
    parser.add_argument("--force", "-f", action="store_true", help="search for process in memory even if does not appear in ps")
    parser.add_argument("--device", "-d", default="emulator-5554", help="specify the device name")
    parser.add_argument("--host", default="127.0.0.1", help="specify adb host")
    parser.add_argument("--port", "-p", type=int, default=5037, help="specify adb port")

    # Mode [pid|name|daemon]
    subparsers = parser.add_subparsers()

    # Search by name mode
    name = subparsers.add_parser("name", help="find a process by name and overwrite credentials")
    name.add_argument("process_name", help="the process name")
    name.set_defaults(mode=Mode.NAME)

    # Search by pid mode
    pid = subparsers.add_parser("pid", help="find a process by PID and overwrite credentials")
    pid.add_argument("pid", type=int, help="the process PID")
    pid.set_defaults(mode=Mode.PID)

    # Daemon mode
    daemon = subparsers.add_parser("daemon", help="overwrite adb daemon credentials")
    daemon.set_defaults(process_name="adbd")
    daemon.set_defaults(mode=Mode.NAME)

    config = parser.parse_args()

    if not hasattr(config, "pid") and not hasattr(config, "process_name"):
        parser.print_help()
        sys.exit(EXIT_ERR)

    return config


def get_log_level(config: argparse.Namespace) -> int:
    if config.quiet:
        return logging.CRITICAL

    if config.verbose:
        return logging.DEBUG

    return logging.INFO


if __name__ == "__main__":
    options = handle_cmd_line()

    logging.basicConfig(format="%(message)s")
    logger.setLevel(get_log_level(options))

    try:
        colorama.init()
    except NameError:
        error("Can't initialize colorama module.")

    title("AERoot (Android Emulator ROOTing system) v. {}\n{}".format(VERSION, LOGO))

    if options.show:
        info("SHOW MODE is ON (device memory will not be modified)")

    try:
        adb = AdbClient(host=options.host, port=options.port)
        adb_device = adb.device(options.device)

        if adb_device is None:
            error("Can't connect to the device", True)

        avd_conf = get_avd(load_avds(options.config_file), adb_device)

        if avd_conf is None:
            error("Android version not supported. Aborting.", True)

        gdb_helper = GdbHelper(arch=avd_conf.get("gdb_arch"))

        info("Detected: {}".format(avd_conf.get("name")))

        if options.mode == Mode.PID:
            target_process = Process(pid=options.pid)
        else:
            target_process = Process(name=options.process_name)

        if not target_process.is_running(adb_device, avd_conf) and not options.force:
            error("Process {} is not running. Aborting.".format(target_process), True)
        else:
            debug("{} process is running".format(target_process))

        info("Search for {} process in memory (this may take a while) ...".format(target_process))

        gdb_helper.start()
        process_addr = find_task_struct(gdb_helper, avd_conf, target_process)

        if process_addr is None:
            error("{} process not found in memory. Aborting.".format(target_process), True)

        if not options.show:
            info("{} process found. Overwriting credentials.".format(target_process))
            overwrite_credentials(gdb_helper, avd_conf, process_addr)

            info("Switching SELinux to permissive...")
            disable_selinux(gdb_helper, avd_conf)
        else:
            show_process_info(gdb_helper, avd_conf, process_addr)
    except GdbTimeoutError:
        error("Gdb timed out. Make sure gdbserver is running on guest (-qemu -s).")
    except RuntimeError as err:
        error(str(err))
    finally:
        if "gdb_helper" in locals() and gdb_helper is not None:
            gdb_helper.stop()
        info("Exiting.")
