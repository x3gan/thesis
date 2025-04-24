from scapy.packet import Packet
from scapy.sendrecv import sendp, sniff

from network.network_interface import NetworkInterface


class ScapyInterface(NetworkInterface):
    def send(self, packet : Packet, interface : str) -> None:
        """Csomag küldése az adott interfészen.
        A paraméterként megkapott csomagot tovább küldi az interfészen.

        Paraméterek:
            packet (Packet) : A küldendő csomag
            interface (str) Az interfész neve
        """
        sendp(x= packet, iface= interface, verbose= False)

    def receive(self, interface : str) -> Packet | None:
        """Csomagok fogadása az adott interfészen.
        A megadott interfészt hálózati csomagokért rövid ideig hallgatózik, ha nem kap,
        akkor üresen tér vissza.

        Paraméterek:
            interface (str) : Az interfész neve.

        Visszatérési érték:
            Packet | None : Ha meghall csomagot, akkor visszaadja, ha nem a következő 'listen' körben újra próbálkozik
        """
        packets = sniff(iface= interface, count= 1, timeout= 1)

        if packets:
            return packets[0]

        return None