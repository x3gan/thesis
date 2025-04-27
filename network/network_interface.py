from abc import ABC, abstractmethod
from scapy.packet import Packet


class NetworkInterface(ABC):
    """Absztrakt osztály hálózati interfész műveletekhez."""

    @abstractmethod
    def send(self, packet: Packet, interface: str) -> None:
        """Csomag küldése interfészen.

        Paraméterek:
            packet (Packet): Az interfészen küldendő csomag.
            interface (str):  A forrás interfész neve.
        """
        ...

    @abstractmethod
    def receive(self, interface: str) -> Packet | None:
        """Csomag fogadása az interfészen.

        Paraméterek:
            interface (str): Figyelt interfész.

        Visszatérési érték:
            _ (Packet | None): Fogadott csomag.

        Megjegyzés:
            A fogadott csomag helyett None-t ad vissza, ha a megadott időkorlát alatt nem
            érkezik csomag.
        """
        ...