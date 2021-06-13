"""
AERoot main module
"""

from enum import IntEnum, auto

from aeroot.avd import Avd, AVDError, AmbiguousProcessNameError


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

            if self.options.mode == Mode.NAME:
                self.options.pid = self.avd.get_pid(self.options.process_name)

            if self.options.pid is None:
                raise ProcessNotRunningError

            self.avd.overwrite_credentials(self.options.pid)
            self.avd.selinux_setenforce(0)
        except AVDError as err:
            raise AERootError(err)
        except AmbiguousProcessNameError:
            msg = (
                "Several processes with the same name are currently running",
                "You should use the pid to target the process"
            )
            raise AERootError("\n".join(msg))


    def cleanup(self):
        if self.avd is not None:
            self.avd.close()
