import logging
from pathlib import Path

from scapy.utils import PcapWriter

class PcapLogger:

    def write_pcap_file(self, pcap_file, packet):
        """A kuldott/elfogott csomagok kiirasa a pcap fileba

        Parameters:
        pcap_file (str): A fájlnak a neve ahova a csomagot bejegyezzuk (nem kell a .pcap)
        packet (Packet): A csomag amit bejegyzunk a pcap fájlba
        """
        file_path = f'packet_logs/{pcap_file}.pcap'

        try:
            pcap_writer = PcapWriter(file_path, append= True, sync= True)
            pcap_writer.write(packet)
        except Exception as e:
            print(f"Hiba történt a hálózati csomag bejegyzése közben: {e}")

    def cleanup(self, name: str, log_dir: str = 'packet_logs') -> None:
        """
        Törli a log és packet_logs mappák tartalmát, kivéve az ignore listán lévő fájlokat
        :return
        """
        folder = log_dir
        ignored_files = {'README.md', '__init__.py', '.gitkeep'}

        try:

            folder_path = Path(folder)
            folder_path.mkdir(exist_ok=True)

            for item in folder_path.iterdir():
                if item.is_file() and item.name not in ignored_files and name in item.name:
                    try:
                        item.unlink()
                    except (PermissionError, FileNotFoundError):
                        logging.error(f"Nem lehetett törölni a fájlt: {item}")
        except FileNotFoundError:
            logging.error(f"A mappa nem található: {folder}")