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
        featureExtractor.extract(packet);
    }
}