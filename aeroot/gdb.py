"""
AERoot GDB module
"""

import re
from time import sleep
from typing import List

from pygdbmi.constants import GdbTimeoutError
from pygdbmi.gdbcontroller import GdbController

from .util import info


class GdbError(Exception): pass


class GdbResponse:

    _SPLITTER = "\\t"


    def __init__(self, raw_response):
        self.raw = raw_response


    def _get_payload(self):
        if len(self.raw) < 2:
            return None

        tokens = self.raw[1].get("payload", "").split(GdbResponse._SPLITTER)

        if len(tokens) < 2:
            return None

        return tokens[1].replace("\\n", "")


    def to_int(self):
        payload = self._get_payload()

        return int(payload, 16) if payload is not None else None


    def to_str(self):
        payload = self._get_payload()

        return payload.replace("\\\"", "") if payload is not None else None


class GdbHelper:

    _WRITE_METHODS = {
        1: "write_byte",
        4: "write_dword",
        8: "write_qword"
    }

    _GDB_PY_PATTERN = re.compile(r"--with-python")


    def __init__(self, arch="x86", timeout=180):
        self.arch = arch
        self.timeout = timeout
        self.gdb = None


    def __init_gdb(self):
        if self.gdb is not None:
            return

        self.gdb = GdbController(time_to_check_for_additional_output_sec=self.timeout)

        if self.arch == "x86_64":
            self.gdb.write("set arch i386:x86-64:intel")


    def exit(self):
        if self.gdb is not None:
            try:
                self.gdb.exit()
            except GdbTimeoutError:
                raise GdbError("Can't connect to gdb server")
            finally:
                self.gdb = None


    def start(self):
        self.__init_gdb()

        try:
            self.gdb.write("target remote :1234")
        except GdbTimeoutError:
            raise GdbError("Can't connect to gdb server")


    def stop(self):
        self.gdb.write("detach")


    def write(self, address: int, value: int, size: int = 1):
        getattr(self, GdbHelper._WRITE_METHODS.get(size, "write_byte"))(address, value)


    def write_byte(self, address: int, value: int):
        self.gdb.write("set *(unsigned char*) (%#x) = %#x" % (address, value))


    def write_dword(self, address: int, value: int):
        self.gdb.write("set *(unsigned int*) (%#x) = %#x" % (address, value))


    def write_qword(self, address: int, value: int):
        self.gdb.write("set *(unsigned long*) (%#x) = %#x" % (address, value))


    def read_dword(self, address: int) -> int:
        return GdbResponse(self.gdb.write("x/wx %#x" % address)).to_int()


    def read_addr(self, address: int) -> int:
        return GdbResponse(self.gdb.write("x/a %#x" % address)).to_int()


    def read_str(self, address: int) -> str:
        return GdbResponse(self.gdb.write("x/s %#x" % address)).to_str()


    def read_ip(self) -> int:
        return GdbResponse(self.gdb.write("p/x $pc")).to_int()


    def find(self, query: str) -> List[int]:
        addresses = []
        response = self.gdb.write("find %s" % query, timeout_sec=180)

        for subset in response:
            payload = subset.get("payload")

            if payload is not None and payload.startswith("0x"):
                addresses.append(int(payload.replace("\\n", ""), 16))

        return addresses


    def execute(self, cmd: str) -> filter:
        result = filter(lambda x: x.get("type") == "console" and x.get("payload").startswith("#"),
                        self.gdb.write(cmd))

        return list(result)


    def execute_and_retry(self, cmd, retry_cnt=5, delay=5, msg="Retry"):
        for i in range(1, retry_cnt + 1):
            if i > 1:
                self.stop()
                sleep(delay)
                self.start()

            result = self.execute(cmd)

            if len(result) > 0:
                return result

            info(f"{msg} (try: {i}/{retry_cnt})...")

        return result


    def has_python(self) -> bool:
        try:
            response = self.gdb.write("show configuration")
        except GdbTimeoutError:
            raise GdbError("Can't connect to gdb server")

        return any(map(lambda x: GdbHelper._GDB_PY_PATTERN.search(x) is not None,
                       (r.get("payload", "") for r in response if r.get("type") == "console")))
