package com.ids.ids_controller.parser;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.springframework.stereotype.Component;

@Component
public class PacketDecoder {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(PacketDecoder.class);
    /**
     * Główna metoda dekodująca surowe bajty na obiekty Pcap4j.
     * @param data tablica bajtów otrzymana z sieci (PcapReceiver)
     */
    public void decode(byte[] data) {
        if (data == null || data.length == 0) return;

        try {
            // Zakładamy, że sonda przesyła ramki Ethernet (Layer 2)
            // Jeśli Twoja sonda wysyła same pakiety IP, zmień na IpV4Packet.newPacket
            Packet ethernetPacket = EthernetPacket.newPacket(data, 0, data.length);

            analyzePacket(ethernetPacket);

        } catch (Exception e) {
            // Logujemy błąd, ale nie zatrzymujemy aplikacji
            //log.warn("Błąd dekodowania ramki: {}. Rozmiar danych: {} bajtów", e.getMessage(), data.length);
        }
    }

    private void analyzePacket(Packet packet) {
        // 1. Sprawdzamy czy wewnątrz ramki Ethernet jest pakiet IPv4
        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
            String srcAddr = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
            String dstAddr = ipV4Packet.getHeader().getDstAddr().getHostAddress();

            // 2. Jeśli to ruch TCP, wyciągamy szczegóły (porty, flagi)
            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
                int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();

                // Sprawdzenie flagi SYN (kluczowe dla wykrywania skanowania portów)
                boolean isSyn = tcpPacket.getHeader().getSyn();

                log.info("[TCP] {}:{} -> {}:{} [SYN: {}]",
                        srcAddr, srcPort, dstAddr, dstPort, isSyn);
            }
            // 3. Opcjonalnie: obsługa innych protokołów (np. UDP, ICMP)
            else {
                log.debug("[IP] {} -> {} (Inny protokół)", srcAddr, dstAddr);
            }
        }
    }
}