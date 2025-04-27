import logging
from pathlib import Path

from scapy.packet import Packet
from scapy.utils import PcapWriter

class PcapLogger:
    """PCAP fájlok kezelésére szolgáló osztály.
    
    Az osztály felelős a hálózati csomagok mentéséért és a PCAP fájlok kezeléséért.
    Lehetővé teszi a csomagok rögzítését PCAP formátumban, valamint a régi naplófájlok törlését.

    Attribútumok:
        log_dir (str): A PCAP fájlok könyvtárának elérési útja.
    """

    def __init__(self, log_dir: str = 'packet_logs'):
        self._log_dir = Path(log_dir)
        self._log_dir.mkdir(exist_ok=True)

    def write_pcap_file(self, pcap_file: str, packet: Packet) -> None:
        """Hálózati csomagot ír a megadott PCAP fájlba (append módban).

        Paraméterek:
            pcap_file (str): A célfájl neve (kiterjesztés nélkül, pl. "R1_eth0").
            packet (Packet): A rögzítendő Scapy csomag.
        """
        file_path = self._log_dir / f"{pcap_file}.pcap"  # Path használata
        try:
            with PcapWriter(str(file_path), append=True, sync=True) as pcap_writer:
                pcap_writer.write(packet)
        except Exception as e:
            logging.error(f"PCAP írási hiba: {e}")

    def cleanup(self, name: str) -> None:
        """Törli a megadott mappából a routerhez tartozó PCAP fájlokat.
        
        Paraméterek:
            name (str): A router neve, csak az ehhez tartozó fájlokat törli
            log_dir (str): A mappa elérési útja, ahonnan törölni kell a fájlokat
        """
        ignored_files = {'README.md', '__init__.py', '.gitkeep'}

        for item in self._log_dir.iterdir():
            if item.is_file() and item.name not in ignored_files and name in item.name:
                item.unlink(missing_ok= True)