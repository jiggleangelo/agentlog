import socket
import urllib.request


def _blocked(*args, **kwargs):
    raise AssertionError("network access is forbidden in tests")

socket.socket = _blocked
urllib.request.urlopen = _blocked
