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

    private final LongAdder inboundBytes = new LongAdder();
    private final LongAdder outboundBytes = new LongAdder();
    private final LongAdder totalPacketCount = new LongAdder();
    private final LongAdder totalPayloadSize = new LongAdder();
    private final Set<String> activeFlows = ConcurrentHashMap.newKeySet();

    // statystyki podstawowe
    private final AtomicInteger synCount = new AtomicInteger(0);
    private final AtomicInteger icmpCount = new AtomicInteger(0);
    private final Map<String, Set<Integer>> portVarietyMap = new ConcurrentHashMap<>();

    private final String PROTECTED_IP = "172.18.0.3"; // adres ofiary z którego można pobierać pliki

    public void extract(Packet packet) {
        if (isTrafficToController(packet)) return;

        int packetSize = packet.length();
        totalPacketCount.increment();
        totalPayloadSize.add(packetSize);

        String srcIp = "";
        String dstIp = "";

        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipPkt = packet.get(IpV4Packet.class);
            srcIp = ipPkt.getHeader().getSrcAddr().getHostAddress();
            dstIp = ipPkt.getHeader().getDstAddr().getHostAddress();

            // Kierunek ruchu
            if (dstIp.equals(PROTECTED_IP)) {
                inboundBytes.add(packetSize);
            } else if (srcIp.equals(PROTECTED_IP)) {
                outboundBytes.add(packetSize);
            }

            // Unikalne przepływy (Flows)
            activeFlows.add(srcIp + "->" + dstIp);
        }

        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            int dstPort = tcp.getHeader().getDstPort().valueAsInt();

            // SYN Flood
            if (tcp.getHeader().getSyn() && !tcp.getHeader().getAck()) {
                synCount.incrementAndGet();
            }

            // NMAP / Entropia Portów
            if (!srcIp.isEmpty()) {
                portVarietyMap.computeIfAbsent(srcIp, k -> ConcurrentHashMap.newKeySet()).add(dstPort);
            }
        }

        if (packet.contains(IcmpV4CommonPacket.class)) {
            IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
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
    public double getAvgPacketSize() {
        long count = totalPacketCount.sum();
        return count == 0 ? 0 : (double) totalPayloadSize.sum() / count;
    }

    public double getTrafficAsymmetry() {
        double in = inboundBytes.sum();
        double out = outboundBytes.sum();
        if (out == 0) return in; // Unikamy dzielenia przez zero
        return in / out; // > 1 ruch przychodzący dominuje (DDoS), < 1 wychodzący (Exfiltration)
    }

    public int getActiveFlowsCount() {
        return activeFlows.size();
    }

    public Map<String, Integer> getAndResetPortVariety() {
        Map<String, Integer> result = new HashMap<>();
        portVarietyMap.forEach((ip, ports) -> result.put(ip, ports.size()));
        portVarietyMap.clear();
        return result;
    }

    // Resetowanie statystyk po zebraniu przez Agregator
    public void resetAll() {
        synCount.set(0);
        icmpCount.set(0);
        totalPacketCount.reset();
        totalPayloadSize.reset();
        inboundBytes.reset();
        outboundBytes.reset();
        portVarietyMap.clear();
        activeFlows.clear();
    }
}
