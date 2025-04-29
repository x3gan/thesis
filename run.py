import sys

from network.network_manager import NetworkManager


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'auto'

    network_manager = NetworkManager()
    network_manager.run(mode)