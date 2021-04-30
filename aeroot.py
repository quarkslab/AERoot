#!/usr/bin/env python3

""" AERoot (Android Emulator Rooting system) """

import argparse
from enum import auto, IntEnum
from hashlib import sha1
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import sys
import yaml

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

VERSION = "experimental"
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

KERNEL_BASE_CMDS = """python
range_start = {}
range_stop = {}
found = False
for addr in range(range_start, range_stop, 0x1000000):
    if found: break

    try:
        gdb.execute("x/a %d"%addr, to_string=True)
        k_addr = addr
        c_addr = addr - 0x100000
        while c_addr > addr - 0x1000000:
            try:
                gdb.execute("x/a %d"%c_addr, to_string=True)
                k_addr = c_addr
                c_addr -= 0x100000
            except gdb.MemoryError:
                print("#%d"%k_addr)
                found = True
                break
    except gdb.MemoryError:
        pass
end"""

TASKLIST_CMDS = """python
a_swapper = {}
o_tasks = {}
o_pid = {}

addr = int(gdb.execute("x/a %d"%(a_swapper + o_tasks), to_string=True).split(":\\t")[1], 16) - o_tasks

while addr != a_swapper:
    pid = gdb.execute("x/wx %d"%(addr + o_pid), to_string=True).split(":\\t")[1]
    pid = int(pid.replace("\\n", ""), 16)
    print("#%d;%d"%(addr, pid))
    addr = int(gdb.execute("x/a %d"%(addr + o_tasks), to_string=True).split(":\\t")[1], 16) - o_tasks
end"""


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


def get_pid(device: ppadb.device.Device, name: str) -> Optional[int]:
    pids = device.shell(f"pidof {name}").replace("\\n", "").split()

    # FIXME If more than one pid is found, should throw an error
    return int(pids[0]) if len(pids) > 0 else None


def get_tasklist(gdb: GdbHelper, tasklist_first_addr: int, o_tasks: int, o_pid: int):
    cmds = TASKLIST_CMDS.format(tasklist_first_addr, o_tasks, o_pid)

    # FIXME DEV
    # print(">>>", gdb.gdb.write("x/a %#x" % tasklist_first_addr))

    response = gdb.gdb.write(cmds)
    results = filter(lambda x: x.get("type") == "console" and x.get("payload").startswith("#"),
                     response)
    tasklist = dict()

    for result in results:
        addr, pid = result.get("payload").replace("\\n", "").replace("#", "", 1).split(";")
        tasklist[int(pid)] = int(addr)

    return tasklist


def find_kernel_base_addr(gdb: GdbHelper, rge_start: int, rge_stop: int) -> Optional[int]:
    cmds = KERNEL_BASE_CMDS.format(rge_start, rge_stop)

    try:
        result = next(filter(lambda x: x.get("type") == "console" and x.get("payload").startswith("#"),
                             gdb.gdb.write(cmds)))

        return int(result.get("payload").replace("#", "").replace("\\n", ""))
    except StopIteration:
        return None


def find_process(tasklist, pid):
    return tasklist.get(int(pid))


def namespace(mapping):
    if isinstance(mapping, dict):
        for k, v in mapping.items():
            mapping[k] = namespace(v)
        return argparse.Namespace(**mapping)
    else:
        return mapping


def get_kernel(device: ppadb.device.Device):
    result = device.shell("uname -rm").strip()
    uname_hash = sha1(result.encode()).hexdigest()
    filename = "{}.yaml".format(uname_hash)

    with open(Path(Path.cwd(), "config", "kernel", filename), "r") as f:
        return namespace(yaml.load(f, yaml.FullLoader))


def overwrite_credentials(gdb: GdbHelper, address: int):
    cmds = [f"x/a {address}", "set $addr = $__"]

    for offset in CAPABILITIES_OFFSETS:
        cmds.append("set *(unsigned int*) ($addr + {}) = {}".format (offset, 0xffffffff))

    for offset in IDS_OFFSETS:
        cmds.append("set *(unsigned int*) ($addr + {}) = {}".format (offset, 0x00000000))

    gdb.gdb.write("\n".join(cmds))


def disable_selinux(gdb: GdbHelper, address, sizeof_enforce):
    debug("SELinux mode found at {}".format(hex(address)))

    gdb.write(address, 0, sizeof_enforce)


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

    title("AERoot (Android Emulator ROOTing system) v. {}".format(VERSION))

    try:
        adb = AdbClient(host=options.host, port=options.port)
        adb_device = adb.device(options.device)

        if adb_device is None:
            error("Can't connect to the device", True)

        try:
            kernel = get_kernel(adb_device)
        except:
            error("Unable to load kernel configuration. Aborting", True)

        gdb_helper = GdbHelper(arch=kernel.arch)

        info("Current kernel is: {}".format(kernel.name))

        if options.mode == Mode.NAME:
            options.pid = get_pid(adb_device, options.process_name)

        if options.pid is None:
            error("Process {} is not running. Aborting.".format(options.pid), True)

        info("Search for process [{}] in memory (this may take a while) ...".format(options.pid))

        gdb_helper.start()
        kernel_base_addr = find_kernel_base_addr(gdb_helper,
                                                 kernel.mem_range.begin,
                                                 kernel.mem_range.end)
        if kernel_base_addr is None:
            error("Unable to find kernel base address. Aborting.", True)

        debug(f"Kernel base address found at: 0x{kernel_base_addr:x}")

        # FIXME
        selinux_addr = kernel_base_addr + kernel.offset.selinux

        tasklist = get_tasklist(gdb_helper,
                                kernel_base_addr + kernel.offset.swapper,
                                kernel.task.offset.tasklist,
                                kernel.task.offset.pid)

        if len(tasklist) == 0:
            error("Unable to retrieve tasklist. Aborting.", True)

        process_addr = find_process(tasklist, options.pid)

        if process_addr is None:
            error("Process [{}] not found in memory. Aborting.".format(options.pid), True)

        info("Process [{}] found. Overwriting credentials.".format(options.pid))
        debug(f"tasks offset {kernel.task.offset.creds}")
        overwrite_credentials(gdb_helper, process_addr + kernel.task.offset.creds)

        info("Switching SELinux to permissive...")
        disable_selinux(gdb_helper,
                        kernel_base_addr + kernel.offset.selinux,
                        kernel.sizeof.enforce)
    except GdbTimeoutError:
        error("Gdb timed out. Make sure gdbserver is running on guest (-qemu -s).")
    except RuntimeError as err:
        error(str(err))
    finally:
        if "gdb_helper" in locals() and gdb_helper is not None:
            gdb_helper.stop()
        info("Exiting.")
