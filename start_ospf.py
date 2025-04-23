import sys
from time import sleep

from monitoring.info_logger import InfoLogger
from network.scapy_interface import ScapyInterface
from ospf_core.ospf import OSPF


CONFIG_PATH = 'config/router.yml'
INFO_LOG_DIR = 'logs'


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python start_ospf.py <router_name>")
        sys.exit(1)

    router_name = sys.argv[1]
    info_logger = InfoLogger(name=router_name, log_dir=INFO_LOG_DIR)
    network_interface = ScapyInterface()

    ospf = OSPF(router_name, CONFIG_PATH, network_interface, info_logger)

    try:
        print(f"Starting OSPF on {router_name}... (Press Ctrl+C to stop)")
        ospf.start()
        while True:
            sleep(0.1)  # CPU terhelés csökkentése
    except KeyboardInterrupt:
        print("\nStopping OSPF...")
    finally:
        ospf.stop()
        print("OSPF stopped.")