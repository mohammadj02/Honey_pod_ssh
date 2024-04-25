#!/usr/bin/env python

import logging
import os
import socket
import sys
import threading
import traceback
import paramiko
import getpass
from binascii import hexlify
from paramiko.py3compat import decodebytes

logging.basicConfig()
logger = logging.getLogger()

# Check if the RSA key file exists
key_filename = "id_rsa"
if not os.path.exists(key_filename):
    print(f"Error: RSA key file '{key_filename}' not found in the current directory ({os.getcwd()}).")
    sys.exit(1)

# Try to load the RSA key, handle encrypted key scenario
try:
    host_key = paramiko.RSAKey(filename=key_filename)
except paramiko.PasswordRequiredException:
    passphrase = getpass.getpass("RSA key passphrase: ")
    try:
        host_key = paramiko.RSAKey(filename=key_filename, password=passphrase)
    except Exception as e:
        print(f"Error loading RSA key with provided passphrase: {str(e)}")
        sys.exit(1)

print("Read key: " + hexlify(host_key.get_fingerprint()).decode('utf-8'))

# Authentication data
data = (
    b"AAAAB3NzaC1yc2EAAAABIwAAAIEAyO4it3fHlmGZWJaGrfeHOVY7RWO3P9M7hp"
    b"fAu7jJ2d7eothvfeuoRFtJwhUmZDluRdFyhFY/hFAh76PJKGAusIqIQKlkJxMC"
    b"KDqIexkgHAfID/6mqvmnSJf0b5W8v5h2pI/stOSwTQ+pxVhwJ9ctYDhRSlF0iT"
    b"UWT10hcuO4Ks8="
)
good_pub_key = paramiko.RSAKey(data=decodebytes(data))


class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.input_buffer = ""

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_gssapi_with_mic(self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None):
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_keyex(self, username, gss_authenticated=paramiko.AUTH_FAILED, cc_file=None):
        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        return False

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True


DoGSSAPIKeyExchange = True

try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", 2200))
except Exception as e:
    print("*** Bind failed: " + str(e))
    traceback.print_exc()
    sys.exit(1)

try:
    sock.listen(100)
    print("Listening for connection ...")
    client, addr = sock.accept()
except Exception as e:
    print("*** Listen/accept failed: " + str(e))
    traceback.print_exc()
    sys.exit(1)

print(f"Got a connection from {addr[0]}:{addr[1]}!")

try:
    t = paramiko.Transport(client)
    try:
        t.load_server_moduli()
    except:
        print("(Failed to load moduli -- gex will be unsupported.)")
        raise
    t.add_server_key(host_key)
    server = Server()
    try:
        t.start_server(server=server)
    except paramiko.SSHException:
        print("*** SSH negotiation failed.")
        sys.exit(1)

    chan = t.accept(20)
    if chan is None:
        print("*** No channel.")
        sys.exit(1)
    print("Authenticated!")

    server.event.wait(10)
    if not server.event.is_set():
        print("*** Client never asked for a shell.")
        sys.exit(1)

    print("SSH connection details:")
    print("Client address:", addr[0])
    print("Client port:", addr[1])
    print("Client SSH version:", t.remote_version)

except Exception as e:
    print("*** Caught exception: " + str(e.__class__) + ": " + str(e))
    traceback.print_exc()
    try:
        t.close()
    except:
        pass
    sys.exit(1)
