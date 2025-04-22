from unittest.mock import Mock

import pytest
from yaml import safe_load

from ospf import OSPF


def test_ospf_initialization():
    """Teszt 1: Létrejön az OSPF-et kezelő osztály a konfigurációs fájl alapján"""
    mock_interface = Mock()
    mock_logger = Mock()

    mock_ospf = OSPF('RT', 'tests/config/ospf_test1.yml', interface= mock_interface, info_logger= mock_logger)
    assert mock_ospf.rid == '1.1.1.1'

def test_hello_packet_sending():
    """Teszt 2: """
    assert True

def test_hello_packet_processing():
    """Teszt 3: """
    assert True

def test_lsa_create():
    """Teszt 4: """
    assert True

def test_lsu_create():
    """Teszt 5: """
    assert True

def test_lsa_process():
    """Teszt 6:"""
    assert True