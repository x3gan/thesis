from scapy.packet import Packet
from scapy.sendrecv import sendp, sniff


class ScapyInterface():
    def send(self, packet, interface : str) -> None:
        """
        Csomag küldése az adott interfészen
        :param packet: A küldendő csomag
        :param interface: Az interfész neve
        :return:
        """
        sendp(x= packet, iface= interface, verbose= False)

    def receive(self, interface : str) -> Packet | None:
        """
        Csomagok fogadása az adott interfészen
        :param interface: Az interfész neve
        :return: A fogadott csomag
        """
        packets = sniff(iface= interface, count= 1, timeout= 1)

        if packets:
            return packets[0]

        return None