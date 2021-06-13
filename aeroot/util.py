"""
AERoot utilities module
"""

import argparse
import logging
import sys

try:
    import colorama
    from colorama import Fore, Style
except ModuleNotFoundError:
    pass

EXIT_ERR = 1


class Logger:

    _instance = None


    @staticmethod
    def init(options):
        logging.basicConfig(format="%(message)s")
        logger = logging.getLogger("AEROOT")
        logger.setLevel(Logger.get_log_level(options) if options is not None else logging.INFO)
        Logger._instance = logger
        colorama.init()


    @staticmethod
    def instance():
        return Logger._instance


    @staticmethod
    def get_log_level(config: argparse.Namespace) -> int:
        if config.quiet:
            return logging.CRITICAL

        if config.verbose:
            return logging.DEBUG

        return logging.INFO


def colorize(msg: str, color: str) -> str:
    return "{}{}{}".format(color, msg, Style.RESET_ALL)


def debug(msg: str):
    try:
        prefix = " [{}]".format(colorize("-", Fore.CYAN))
    except NameError:
        prefix = " [-]"

    Logger.instance().debug("%s %s", prefix, msg)


def error(msg: str, do_exit: bool = False):
    try:
        prefix = "[{}]".format(colorize("!", Fore.RED))
    except NameError:
        prefix = "[!]"

    for line in msg.split("\n"):
        Logger.instance().error("%s %s", prefix, line)

    if do_exit:
        sys.exit(EXIT_ERR)


def info(msg: str):
    try:
        prefix = "[{}]".format(colorize("+", Fore.GREEN))
    except NameError:
        prefix = "[+]"

    Logger.instance().info("%s %s", prefix, msg)


def title(msg: str):
    try:
        Logger.instance().info(colorize(msg, Fore.BLUE))
    except NameError:
        Logger.instance().info(msg)
