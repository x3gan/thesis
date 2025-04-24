import sys
from time import sleep

from monitoring.info_logger import InfoLogger
from network.scapy_interface import ScapyInterface
from ospf_core.ospf import OSPF


CONFIG_PATH  = 'config/router.yml'
INFO_LOG_DIR = 'logs'


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Hasznalat: sudo python3 start_ospf.py <router_neve>")
        sys.exit(1)

    router_name       = sys.argv[1]
    info_logger       = InfoLogger(name=router_name, log_dir=INFO_LOG_DIR)
    network_interface = ScapyInterface()

    ospf = OSPF(router_name, CONFIG_PATH, network_interface, info_logger)

    try:
        ospf.start()
        while ospf.is_running:
            sleep(0.5)
    except KeyboardInterrupt:
        print("\nLeállítási parancsot kapott... (CTRL + C)")
        ospf.stop()
    finally:
        print("Az OSPF futása leállt.")