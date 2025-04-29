import os
import socket
import fcntl
import struct

from scapy.utils import PcapWriter
from yaml import safe_load


def get_config(filepath: str) -> dict | None:
    """Kiolvassa a konfigurációt a megadott konfigurációs fájlból.

    Paraméterek:
        filepath (str): A konfigurációs fájl útvonala.
    """
    with open(filepath, 'r') as file:
        config = safe_load(file)

    if is_config_valid(config):
        return config

def is_config_valid(config: dict) -> bool:
    return True
