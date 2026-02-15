package com.ids.ids_controller.parser;

import org.pcap4j.packet.*;
import org.springframework.stereotype.Component;

@Component
public class PacketDecoder {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(PacketDecoder.class);
    /**
     * Główna metoda dekodująca surowe bajty na obiekty Pcap4j.
     * @param data tablica bajtów otrzymana z sieci (PcapReceiver)
     */
    public void decode(byte[] data) {
        if (data == null || data.length < 14) return;

        try {
            // Sprawdzenie czy to nie jest nagłówek pliku PCAP (zaczyna się od 0xa1b2c3d4 lub 0xd4c3b2a1)
            // Jeśli tak, ignorujemy te 24 bajty i szukamy dalej
            int offset = 0;
            if (data.length >= 24 && (data[0] == (byte)0xa1 && data[1] == (byte)0xb2 || data[0] == (byte)0xd4)) {
                log.info("Wykryto nagłówek globalny PCAP - pomijam 24 bajty");
                offset = 24;
            }

            // Próbujemy wyłuskać pakiet.
            // W strumieniu PCAP przed każdym pakietem jest 16 bajtów nagłówka rekordu (timestamp itp.)
            // Jeśli Twoja sonda wysyła surowe ramki, offset będzie 0.
            // Jeśli wysyła strumień PCAP, musimy przeskoczyć nagłówek rekordu.

            // Spróbujmy dekodować od różnych offsetów, aż trafimy w ramkę Ethernet
            Packet packet = null;
            try {
                packet = EthernetPacket.newPacket(data, offset, data.length - offset);
            } catch (Exception e) {
                // Jeśli nie Ethernet, spróbuj przesunąć o 16 bajtów (nagłówek pakietu PCAP)
                if (data.length > offset + 16) {
                    packet = EthernetPacket.newPacket(data, offset + 16, data.length - offset - 16);
                }
            }

            if (packet != null) {
                analyzePacket(packet);
            }

        } catch (Exception e) {
            // Cichy debug, żeby nie spamować
            log.debug("Nie udało się zinterpretować fragmentu danych: {}", e.getMessage());
        }
    }

    private void analyzePacket(Packet packet) {
        if (packet.contains(IcmpV4CommonPacket.class)) {
            log.info("[ICMP] Przechwycono PING!");
        }
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