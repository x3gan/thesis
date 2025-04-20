from abc import ABC, abstractmethod

from scapy.packet import Packet


class AbstractInterface(ABC):
    @abstractmethod
    def send(self, packet : Packet, interface : str) -> None:
        """
        Csomag küldése az adott interfészen
        :param packet: A küldendő csomag
        :param interface: Az interfész neve amelyik kiküldi a csomagot
        :return:
        """
        pass

    @abstractmethod
    def receive(self, interface : str) -> Packet:
        """
        Csomagok fogadása az adott interfészen
        :param interface: Az interfész neve amelyik fogadja a csomagot
        :return: A fogadott csomag
        """
        pass
