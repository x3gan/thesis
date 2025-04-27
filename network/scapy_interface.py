from scapy.packet import Packet
from scapy.sendrecv import sendp, sniff

from network.network_interface import NetworkInterface


class ScapyInterface(NetworkInterface):
    """Hálózati csomagküldés és fogadás megvalósítás a Scapy csomagküldő segítségével. """

    def send(self, packet: Packet, interface: str) -> None:
        """Csomag küldése az adott interfészen.

        A paraméterként megkapott csomagot tovább küldi az interfészen.

        Paraméterek:
            packet (Packet): A küldendő Scapy csomag
            interface (str): A küldő interfész neve
        """
        sendp(x= packet, iface= interface, verbose= False)

    def receive(self, interface: str) -> Packet | None:
        """Csomagok fogadása az adott interfészen.

        A megadott interfészt hálózati csomagokért rövid ideig hallgatózik, ha nem kap,
        akkor üresen tér vissza.

        Megjegyzés:
            - Ha 2 másodperc alatt nem kap csomagot, akkor None értékkel tér vissza.

        Paraméterek:
            interface (str): A figyelt interfész neve.

        Visszatérési érték:
            _ (Packet | None): Ha meghall csomagot, akkor visszaadja, ha nem a következő 'listen'
            körben újra próbálkozik
        """
        packets = sniff(iface= interface, count= 1, timeout= 2)

        if packets:
            return packets[0]

        return None