package com.ids.ids_controller.service;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.springframework.stereotype.Service;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class FeatureExtractor {
    private static final Logger log = LoggerFactory.getLogger(FeatureExtractor.class);

    // Liczniki dla logiki rozmytej
    private final AtomicInteger synCount = new AtomicInteger(0);
    private final AtomicInteger icmpCount = new AtomicInteger(0);

    public void extract(Packet packet) {
        // 1. Filtrowanie - ignoruj ruch do kontrolera (port 9000), żeby uniknąć pętli
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            if (tcp.getHeader().getDstPort().valueAsInt() == 9000) {
                return;
            }

            // 2. Liczenie pakietów SYN (potencjalny skan)
            if (tcp.getHeader().getSyn()) {
                int currentSyn = synCount.incrementAndGet();
                log.info("!!! Wykryto SYN [Suma: {}]", currentSyn);
            }
        }

        // 3. Liczenie pakietów ICMP (potencjalny Ping Sweep)
        if (packet.contains(IcmpV4CommonPacket.class)) {
            int currentIcmp = icmpCount.incrementAndGet();
            log.info("!!! Wykryto ICMP (PING) [Suma: {}]", currentIcmp);
        }
    }

    // Metoda, którą wywoła logika rozmyta co sekundę
    public int getAndResetSynCount() {
        return synCount.getAndSet(0);
    }
}
