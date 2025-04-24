from abc import ABC, abstractmethod
from scapy.packet import Packet


class NetworkInterface(ABC):
    @abstractmethod
    def send(self, packet : Packet, interface : str) -> None: ...

    @abstractmethod
    def receive(self, interface : str) -> Packet | None: ...