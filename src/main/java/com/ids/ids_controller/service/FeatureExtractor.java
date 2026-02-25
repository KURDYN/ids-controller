package com.ids.ids_controller.service;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class FeatureExtractor {
    private static final Logger log = LoggerFactory.getLogger(FeatureExtractor.class);

    // statystyki podstawowe
    private final AtomicInteger synCount = new AtomicInteger(0);
    private final AtomicInteger icmpCount = new AtomicInteger(0);

    // statystyki szczegółowe dla konkretnych ataków
    private final Map<String, Set<Integer>> portVarietyMap = new ConcurrentHashMap<>(); // NMAP: IP -> unikalne porty
    private final AtomicInteger sshAttemptCount = new AtomicInteger(0); // Brute-force na porcie 22
    private final LongAdder totalBytes = new LongAdder();

    public void extract(Packet packet) {
        if (isTrafficToController(packet)) return;

        totalBytes.add(packet.length());

        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            int dstPort = tcp.getHeader().getDstPort().valueAsInt();

            // Atak: DoS/SYN Flood
            if (tcp.getHeader().getSyn() && !tcp.getHeader().getAck()) {
                synCount.incrementAndGet();
            }

            // Atak: NMAP/Scanning (agregacja unikalnych portów na IP)
            if (packet.contains(IpV4Packet.class)) {
                String srcIp = packet.get(IpV4Packet.class).getHeader().getSrcAddr().getHostAddress();
                portVarietyMap.computeIfAbsent(srcIp, k -> ConcurrentHashMap.newKeySet()).add(dstPort);
            }

            // Atak: SSH Brute-Force (port 22 + flaga PSH/ACK sugerująca próbę logowania)
            if (dstPort == 22 && tcp.getHeader().getPsh()) {
                sshAttemptCount.incrementAndGet();
            }
        }

        if (packet.contains(IcmpV4CommonPacket.class)) {
            IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
            // tylko Echo Request (Typ 8), ignorujemy odpowiedzi
            if (icmp.getHeader().getType().value() == (byte) 8) {
                icmpCount.incrementAndGet();
            }
        }
    }

    private boolean isTrafficToController(Packet packet) {
        if (packet.contains(TcpPacket.class)) {
            return packet.get(TcpPacket.class).getHeader().getDstPort().valueAsInt() == 9000;
        }
        return false;
    }

    // Metody eksportujące dane do Agregatora Statystyk
    public int getAndResetSynCount() { return synCount.getAndSet(0); }
    public int getAndResetIcmpCount() { return icmpCount.getAndSet(0); }
    public int getAndResetSshAttempts() { return sshAttemptCount.getAndSet(0); }

    public Map<String, Integer> getAndResetPortVariety() {
        Map<String, Integer> result = new HashMap<>();
        portVarietyMap.forEach((ip, ports) -> result.put(ip, ports.size()));
        portVarietyMap.clear();
        return result;
    }
}
