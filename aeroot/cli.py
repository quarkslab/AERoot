"""
AERoot CLI module (Entry Point)
"""

import argparse
import sys

from aeroot import __version__
from aeroot.aeroot import AERoot, Mode, ProcessNotRunningError, AERootError
from aeroot.util import Logger, error, info, title, EXIT_ERR


def handle_cmd_line() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AERoot (Android Emulator ROOTing system) v. {}".format(__version__)
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--verbose", "-v", action="store_true", help="show debug level messages")
    group.add_argument("--quiet", "-q", action="store_true", help="quiet output")
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


def main():
    options = handle_cmd_line()
    Logger.init(options)

    title("AERoot (Android Emulator ROOTing system) v. {}".format(__version__))

    aeroot = AERoot(options)

    try:
        aeroot.do_root()
    except AERootError as err:
        error(f"{err} **Aborting**")
    except ProcessNotRunningError:
        error("Process is not running. Aborting")
    finally:
        aeroot.cleanup()
        info("Exiting")
