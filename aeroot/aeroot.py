"""
AERoot main module
"""

from enum import IntEnum, auto

from aeroot.avd import Avd, ADBError, AVDError


class ProcessNotRunningError(Exception): pass
class AERootError(Exception): pass


class Mode(IntEnum):
    PID = auto()
    NAME = auto()


class AERoot:

    def __init__(self, options):
        self.options = options
        self.avd = None


    def do_root(self):
        try:
            self.avd = Avd(self.options.device, self.options.host, self.options.port)
        except ADBError:
            raise AERootError("Can't connect through ADB")

        if self.options.mode == Mode.NAME:
            self.options.pid = self.avd.get_pid(self.options.process_name)

        if self.options.pid is None:
            raise ProcessNotRunningError

        try:
            self.avd.overwrite_credentials(self.options.pid)
            self.avd.selinux_setenforce(0)
        except AVDError as err:
            raise AERootError(err)


    def cleanup(self):
        if self.avd is not None:
            self.avd.close()
