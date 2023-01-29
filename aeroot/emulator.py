"""
Emulator console module
"""

import socket
import re
import telnetlib


class ConsoleError(Exception):
    pass


class Console:

    _AUTH_TOKEN_PATTERN = re.compile(r"'(.*\.emulator(?:_console)?_auth_token)'")

    def __init__(self, host="127.0.0.1", port=5554):
        self.emulator_telnet_host = host
        self.emulator_telnet_port = port
        self.sock = None

    def connect(self):
        try:
            self.sock = telnetlib.Telnet(
                self.emulator_telnet_host, self.emulator_telnet_port, 1
            )
            reply = self.sock.read_until(b"OK", 1.0).decode("utf-8")

            if not self._authenticate(reply):
                raise ConsoleError("Emulator console authentication error")
        except socket.error:
            raise ConsoleError("Emulator console connection error")

    def disconnect(self):
        self.sock.close()

    def send_cmd(self, cmd):
        self.sock.write(f"{cmd}\n".encode())
        return self.sock.read_until(b"OK", 60.0).decode("utf-8")

    def _authenticate(self, reply):
        token = Console._get_auth_token(reply)

        if token is None:
            return False

        return "OK" in self.send_cmd(f"auth {token}")

    @staticmethod
    def _get_auth_token(reply):
        result = Console._AUTH_TOKEN_PATTERN.search(reply)

        if len(result.groups()) == 0:
            return None

        token_file = result.group(1)

        with open(token_file, "r") as token_f:
            return token_f.read().strip()
