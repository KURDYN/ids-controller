package com.ids.ids_controller.parser;

import com.ids.ids_controller.service.FeatureExtractor;
import com.ids.ids_controller.service.IncidentService;
import org.pcap4j.packet.*;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/ - struktura pcap
 * */

@Component
public class PacketDecoder {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(PacketDecoder.class); // inicjacja logowania

    private final FeatureExtractor featureExtractor;
    private final IncidentService incidentService;

    private static class SensorDecoderState {
        boolean isBigEndian = false;
        boolean globalHeaderParsed = false;
        byte[] remainder = null;
    }

    private final Map<String, SensorDecoderState> sensorStates = new ConcurrentHashMap<>();

    // Wstrzyknięcie serwisu ekstraktora cech przez konstruktor
    public PacketDecoder(FeatureExtractor featureExtractor, IncidentService incidentService) {
        this.featureExtractor = featureExtractor;
        this.incidentService = incidentService;
    }

    /*
     * główna metoda dekodująca surowe bajty odebrane z sieci.
     * obsługuje format strumienia PCAP (Global Header + Packet Records).
     */
    public synchronized void decode(byte[] incomingData, String sensorId) {
        SensorDecoderState state = sensorStates.computeIfAbsent(sensorId, k -> new SensorDecoderState());

        // Minimalna ramka Ethernet to 14 bajtów (MAC src, MAC dst, EtherType)
        byte[] data;

        synchronized (state) {
            if (state.remainder != null) {
                data = new byte[state.remainder.length + incomingData.length];
                System.arraycopy(state.remainder, 0, data, 0, state.remainder.length);
                System.arraycopy(incomingData, 0, data, state.remainder.length, incomingData.length);
                state.remainder = null;
            } else {
                data = incomingData;
            }

            if (data == null || data.length < 14) return;

            int offset = 0;

            /* * sprawdzenie tzw. "Magic Number" nagłówka globalnego PCAP (24 bajty).
             * 0xa1b2c3d4/0xa1b23c4d oznacza standardowy format, 0xd4c3b2a1/0x4d3cb2a1 to format zamieniony.
             * na maszynie Big-Endian, w pamięci bajty leżą po kolei: A1 B2 C3 D4. (Network Byte Order)
             * na maszynie Little-Endian, ta sama liczba jest "odwrócona" w bajtach: D4 C3 B2 A1 (x86 (Intel/AMD)).
             * jeśli go wykryjemy na początku bufora, przesuwamy wskaźnik o 24 bajty.
             */

            // 0xA1 -> Big-Endian (zarówno microsec jak i nano zaczynają się od 0xA1...)
            // 0xD4 -> Little-Endian microsec (D4 C3 B2 A1)
            // 0x4D -> Little-Endian nanosec (4D 3C B2 A1)
            if (!state.globalHeaderParsed && data.length >= 24) {
                if (data[0] == (byte) 0xa1 && data[1] == (byte) 0xb2) {
                    state.isBigEndian = true;
                    byte[] pcapHeader = new byte[24];
                    System.arraycopy(data, 0, pcapHeader, 0, 24);
                    incidentService.setGlobalHeader(sensorId, pcapHeader);
                    offset = 24;
                    state.globalHeaderParsed = true;
                } else if ((data[0] == (byte) 0xd4 && data[1] == (byte) 0xc3 || data[0] == (byte) 0x4d && data[1] == (byte) 0x3c)) {
                    state.isBigEndian = false;
                    byte[] pcapHeader = new byte[24];
                    System.arraycopy(data, 0, pcapHeader, 0, 24);
                    incidentService.setGlobalHeader(sensorId, pcapHeader);
                    offset = 24;
                    state.globalHeaderParsed = true;
                }
            }

            /*
             * pętla przetwarzająca bufor. Każdy rekord pakietu w PCAP ma 16-bajtowy nagłówek.
             * offset musi pozwalać na odczyt przynajmniej tego nagłówka.
             */
            while (offset + 16 < data.length) {
                try {
                    /*
                     * Wyciąganie długości pakietu (incl_len) z nagłówka rekordu PCAP.
                     * Długość znajduje się na bajtach 8-11 nagłówka rekordu.
                     * Używamy operacji bitowych (przesunięcia i maskowanie 0xff),
                     * aby złożyć 4 bajty w jedną liczbę całkowitą.
                     */
                    int packetLen;
                    if (state.isBigEndian) {
                        // Big-Endian: najbardziej znaczący bajt jest pierwszy (offset + 8)
                        packetLen = ((data[offset + 8] & 0xff) << 24) |
                                ((data[offset + 9] & 0xff) << 16) |
                                ((data[offset + 10] & 0xff) << 8) |
                                (data[offset + 11] & 0xff);
                    } else {
                        // Little-Endian: najmniej znaczący bajt jest pierwszy (offset + 11)
                        packetLen = ((data[offset + 11] & 0xff) << 24) |
                                ((data[offset + 10] & 0xff) << 16) |
                                ((data[offset + 9] & 0xff) << 8) |
                                (data[offset + 8] & 0xff);
                    }

                    // Walidacja: czy odczytana długość ma sens i czy pakiet mieści się w tablicy
                    if (packetLen <= 0) {
                        offset++;
                        continue;
                    }

                    if (offset + 16 + packetLen > data.length) {
                        // Pakiet jest ucięty - kończymy przetwarzanie tego bufora i wychodzimy do sekcji remainder
                        break;
                    }

                    try {
                        byte[] fullPacketRecord = new byte[16 + packetLen];
                        System.arraycopy(data, offset, fullPacketRecord, 0, 16 + packetLen);
                        incidentService.registerPacket(sensorId, fullPacketRecord);
                        // Kopiujemy tylko czyste dane ramki Ethernet (pomijając 16 bajtów nagłówka rekordu)
                        byte[] ethernetRaw = new byte[packetLen];
                        System.arraycopy(data, offset + 16, ethernetRaw, 0, packetLen);
                        // Fabryka Pcap4j tworzy obiektowy model pakietu z surowych bajtów
                        Packet packet = EthernetPacket.newPacket(ethernetRaw, 0, ethernetRaw.length);
                        featureExtractor.extract(packet, sensorId);
                    } catch (Exception e) {
                        log.error("Błąd parsowania pakietu na offset {}: {}", offset, e.getMessage());
                    }

                    // Przesuwamy offset o cały przetworzony rekord (nagłówek 16B + dane pakietu)
                    offset += 16 + packetLen;

                } catch (Exception e) {
                    // W razie błędu parsowania konkretnego pakietu, idziemy o bajt dalej, by nie zablokować pętli
                    offset++;
                }
            }
            if (offset < data.length) {
                state.remainder = new byte[data.length - offset];
                System.arraycopy(data, offset, state.remainder, 0, state.remainder.length);
            }
        }
    }
}