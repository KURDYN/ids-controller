package com.ids.ids_controller.parser;

import com.ids.ids_controller.service.FeatureExtractor;
import org.pcap4j.packet.*;
import org.springframework.stereotype.Component;

@Component
public class PacketDecoder {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(PacketDecoder.class);

    private final FeatureExtractor featureExtractor;

    public PacketDecoder(FeatureExtractor featureExtractor) {
        this.featureExtractor = featureExtractor;
    }

    /**
     * Główna metoda dekodująca surowe bajty na obiekty Pcap4j.
     * @param data tablica bajtów otrzymana z sieci (PcapReceiver)
     */
    public void decode(byte[] data) {
        if (data == null || data.length < 14) return;

        int offset = 0;

        // 1. Obsługa nagłówka globalnego (tylko na starcie strumienia)
        if (data.length >= 24 && (data[0] == (byte)0xa1 && data[1] == (byte)0xb2 || data[0] == (byte)0xd4)) {
            log.info("Pomijam nagłówek globalny PCAP");
            offset = 24;
        }

        // 2. Pętla - czytaj dopóki w buforze są dane
        while (offset + 16 < data.length) {
            try {
                // W formacie PCAP nagłówek rekordu (16 bajtów) ma długość pakietu na pozycjach 8-12 (Little Endian)
                // Pobieramy długość zapisaną w nagłówku PCAP, aby wiedzieć ile bajtów wyciąć
                int packetLen = ((data[offset + 11] & 0xff) << 24) |
                        ((data[offset + 10] & 0xff) << 16) |
                        ((data[offset + 9] & 0xff) << 8) |
                        (data[offset + 8] & 0xff);

                if (packetLen <= 0 || offset + 16 + packetLen > data.length) {
                    // Jeśli długość jest nierealna lub wychodzi poza bufor - szukamy następnej ramki Ethernet
                    offset++;
                    continue;
                }

                // Wycinamy surową ramkę Ethernet
                byte[] ethernetRaw = new byte[packetLen];
                System.arraycopy(data, offset + 16, ethernetRaw, 0, packetLen);

                Packet packet = EthernetPacket.newPacket(ethernetRaw, 0, ethernetRaw.length);
                analyzePacket(packet);

                // Przesuwamy offset o nagłówek (16) + dane pakietu
                offset += 16 + packetLen;

            } catch (Exception e) {
                offset++; // W razie błędu przesuń o 1 bajt i próbuj dalej
            }
        }
    }

    private void analyzePacket(Packet packet) {
        featureExtractor.extract(packet);
    }
}