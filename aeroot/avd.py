"""
AERoot AVD module
"""

from argparse import Namespace
from functools import lru_cache
from pathlib import Path

import yaml
from ppadb.client import Client as AdbClient

from aeroot.gdb import GdbHelper, GdbError
from aeroot.util import debug, info

class AmbiguousProcessNameError(Exception): pass
class GdbPythonSupportError(Exception): pass
class AVDError(Exception): pass


class Avd:

    _TASKLIST_CMD = (
        "python",
        "a_swapper = {}",
        "o_tasks = {}",
        "o_pid = {}",

        "addr = gdb.execute('x/a %d'%(a_swapper + o_tasks), to_string=True).split(':\\t')[1]",
        "addr = int(addr, 16) - o_tasks",

        "while addr != a_swapper:",
        "   pid = gdb.execute('x/wx %d'%(addr + o_pid), to_string=True).split(':\\t')[1]",
        "   pid = int(pid.replace('\\n', ''), 16)",
        "   print('#%d;%d'%(addr, pid))",
        "   addr = gdb.execute('x/a %d'%(addr + o_tasks), to_string=True).split(':\\t')[1]",
        "   addr = int(addr, 16) - o_tasks",
        "end"
    )

    _CAPABILITIES_OFFSETS = [0x30, 0x34, 0x38, 0x3c, 0x40, 0x44]
    _IDS_OFFSETS = [0x04, 0x08, 0x0c, 0x10, 0x14, 0x18, 0x1c, 0x20, 0x24]


    def __init__(self, device: str, host: str, port: int):
        self._tasklist = None

        try:
            self.device = AdbClient(host=host, port=port).device(device)
        except RuntimeError as err:
            raise AVDError(err)

        if self.device is None:
            raise AVDError("Can't connect to emulator through ADB")


    @property
    @lru_cache(maxsize=1)
    def kernel(self):
        config_name = "{}.yaml".format(self.device.shell("uname -rm").replace(" ", "_").strip())
        root_path = Path(__file__).resolve().parent.parent

        return Kernel.load(root_path / "config" / "kernel" / config_name)


    @property
    def tasklist(self):
        if self._tasklist is not None:
            return self._tasklist

        debug("Retrieving tasklist from memory")

        cmd = "\n".join(Avd._TASKLIST_CMD).format(self.kernel.swapper_address,
                                                  self.kernel.config.task.offset.tasklist,
                                                  self.kernel.config.task.offset.pid)

        try:
            results = self.kernel.gdb.execute_and_retry(cmd, msg="Wait for kernel memory mapping")
        except GdbError as err:
            raise AVDError(err)

        tasklist = dict()

        for result in results:
            addr, pid = result.get("payload").replace("\\n", "").replace("#", "", 1).split(";")
            tasklist[int(pid)] = int(addr)

        self._tasklist = tasklist if len(tasklist) > 0 else None
        return self._tasklist


    def find_process(self, pid: int):
        info(f"Kernel base address found at 0x{self.kernel.base_address:x}")

        tasklist = self.tasklist

        if tasklist is None:
            raise AVDError("Can't retrieve tasklist from emulator memory")

        paddr = tasklist.get(int(pid))
        info(f"Process [{pid}] found at 0x{paddr:x}")

        return paddr


    def get_pid(self, pname: str) -> int:
        pids = self.device.shell(f"pidof {pname}").replace("\\n", "").split()

        if len(pids) > 1:
            raise AmbiguousProcessNameError()

        return int(pids[0]) if len(pids) > 0 else None


    def overwrite_credentials(self, pid):
        address = self.find_process(pid) + self.kernel.config.task.offset.creds
        cmd = [f"x/a {address}", "set $addr = $__"]

        for offset in Avd._CAPABILITIES_OFFSETS:
            cmd.append("set *(unsigned int*) ($addr + {}) = {}".format(offset, 0xffffffff))

        for offset in Avd._IDS_OFFSETS:
            cmd.append("set *(unsigned int*) ($addr + {}) = {}".format(offset, 0x00000000))

        info(f"Overwriting process [{pid}] credentials")

        self.kernel.gdb.execute("\n".join(cmd))


    def selinux_setenforce(self, mode: int):
        self.kernel.enforce = mode


    def close(self):
        try:
            self.kernel.gdb.exit()
        except AVDError:
            pass


class Kernel:

    _KERNEL_BASE_CMD = (
        "python",
        "range_start = {}",
        "range_stop = {}",
        "found = False",

        "for addr in range(range_start, range_stop, 0x1000000):",
        "   if found: break",

        "   try:",
        "       gdb.execute('x/a %d'%addr, to_string=True)",
        "       k_addr = addr",
        "       c_addr = addr - 0x100000",
        "       while c_addr > addr - 0x1000000:",
        "           try:",
        "               gdb.execute('x/a %d'%c_addr, to_string=True)",
        "               k_addr = c_addr",
        "               c_addr -= 0x100000",
        "           except gdb.MemoryError:",
        "               print('#%d'%k_addr)",
        "               found = True",
        "               break",
        "   except gdb.MemoryError:",
        "       pass",
        "end"
    )


    def __init__(self, config):
        self.config = config
        self._base_address = None


    @property
    @lru_cache(maxsize=1)
    def gdb(self):
        gdb = GdbHelper(arch=self.config.arch)

        try:
            gdb.start()

            if not gdb.has_python():
                raise GdbPythonSupportError
        except GdbError as err:
            raise AVDError(err)

        return gdb


    @property
    def base_address(self):
        if self._base_address is not None:
            return self._base_address

        debug("Retrieving kernel base address from memory")

        cmd = "\n".join(Kernel._KERNEL_BASE_CMD).format(self.config.mem_range.begin,
                                                        self.config.mem_range.end)

        try:
            result = self.gdb.execute_and_retry(cmd, msg="Wait for kernel memory mapping")
        except GdbError as err:
            raise AVDError(err)

        if len(result) == 0:
            raise AVDError("Can't retrieve kernel base from memory")

        self._base_address = int(result[0].get("payload").replace("#", "").replace("\\n", ""))
        return self._base_address


    @property
    @lru_cache(maxsize=1)
    def selinux_address(self):
        return self.base_address + self.config.offset.selinux


    @property
    @lru_cache(maxsize=1)
    def swapper_address(self):
        return self.base_address + self.config.offset.swapper


    @property
    def enforce(self):
        return self.gdb.read_dword(self.selinux_address)


    @enforce.setter
    def enforce(self, mode):
        info(f"Set SELinux enforce (0x{self.selinux_address:x}) to {mode}")
        self.gdb.write(self.selinux_address, mode, self.config.sizeof.enforce)


    @staticmethod
    def load(filename):
        with open(Path(Path.cwd(), "config", "kernel", filename), "r") as fconfig:
            config = Kernel._get_config(yaml.load(fconfig, yaml.FullLoader))

            return Kernel(config)


    @staticmethod
    def _get_config(mapping):
        if isinstance(mapping, dict):
            for key, value in mapping.items():
                mapping[key] = Kernel._get_config(value)
            return Namespace(**mapping)

        return mapping
