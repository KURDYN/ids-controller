package com.ids.ids_controller.service;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class FeatureExtractor {
    private static final Logger log = LoggerFactory.getLogger(FeatureExtractor.class);

    private final Map<String, SensorState> sensorStates = new ConcurrentHashMap<>();

    private static class SensorState {
        final LongAdder inboundBytes = new LongAdder();
        final LongAdder outboundBytes = new LongAdder();
        final LongAdder totalPacketCount = new LongAdder();
        final LongAdder totalPayloadSize = new LongAdder();
        final Set<String> activeFlows = ConcurrentHashMap.newKeySet();

        final AtomicInteger synCount = new AtomicInteger(0);
        final AtomicInteger icmpCount = new AtomicInteger(0);
        final Map<String, Set<Integer>> portVarietyMap = new ConcurrentHashMap<>();

        // Zbiory na potrzeby rejestracji IP w Incydentach
        final Set<String> sourceIps = ConcurrentHashMap.newKeySet();
        private volatile String lastTargetIp = null;
    }

    public void extract(Packet packet, String sensorId) {
        if (isTrafficToController(packet)) return;


        SensorState state = sensorStates.computeIfAbsent(sensorId, k -> new SensorState());

        int packetSize = packet.length();
        state.totalPacketCount.increment();
        state.totalPayloadSize.add(packetSize);

        String srcIp = "";
        String dstIp = "";

        if (packet.contains(IpV4Packet.class)) {
            IpV4Packet ipPkt = packet.get(IpV4Packet.class);
            if (ipPkt.getHeader().getSrcAddr().isLoopbackAddress() ||
                    ipPkt.getHeader().getSrcAddr().isAnyLocalAddress() ||
                    ipPkt.getHeader().getSrcAddr().isMulticastAddress()) {
                return;
            }
            srcIp = ipPkt.getHeader().getSrcAddr().getHostAddress();
            dstIp = ipPkt.getHeader().getDstAddr().getHostAddress();

            // Rejestracja adresów IP do incydentu (wykorzystuje Pcap4j)
            state.sourceIps.add(srcIp);
            if (!dstIp.equals("255.255.255.255") && !dstIp.startsWith("224.")) {
                state.lastTargetIp = dstIp;
            }

            // Unikalne przepływy
            state.activeFlows.add(srcIp + "->" + dstIp);
        }

        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            int dstPort = tcp.getHeader().getDstPort().valueAsInt();

            if (tcp.getHeader().getSyn() && !tcp.getHeader().getAck()) {
                state.synCount.incrementAndGet();
            }

            if (!srcIp.isEmpty()) {
                state.portVarietyMap.computeIfAbsent(srcIp, k -> ConcurrentHashMap.newKeySet()).add(dstPort);
            }
        }

        if (packet.contains(IcmpV4CommonPacket.class)) {
            IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
            if (icmp.getHeader().getType().value() == (byte) 8) {
                state.icmpCount.incrementAndGet();
            }
        }
    }

    private boolean isTrafficToController(Packet packet) {
        if (packet.contains(TcpPacket.class)) {
            return packet.get(TcpPacket.class).getHeader().getDstPort().valueAsInt() == 9000 || packet.get(TcpPacket.class).getHeader().getSrcPort().valueAsInt() == 9000;
        }
        return false;
    }

    // Pobieranie zgromadzonych IP dla Incydentu

    public List<String> getDetectedSourceIps(String sensorId) {
        SensorState state = sensorStates.get(sensorId);
        if (state == null) return Collections.emptyList();

        // Pobieramy kopię zebranych IP i czyścimy bufor pod kątem kolejnych incydentów
        List<String> ips = new ArrayList<>(state.sourceIps);
        state.sourceIps.clear();
        return ips;
    }

    public String getDetectedTargetIp(String sensorId) {
        SensorState state = sensorStates.get(sensorId);
        return state == null ? null : state.lastTargetIp;
    }

    // Standardowe metody pobierające statystyki
    public int getAndResetSynCount(String sensorId) {
        SensorState state = sensorStates.get(sensorId);
        return state == null ? 0 : state.synCount.getAndSet(0);
    }

    public int getAndResetIcmpCount(String sensorId) {
        SensorState state = sensorStates.get(sensorId);
        return state == null ? 0 : state.icmpCount.getAndSet(0);
    }

    public double getAvgPacketSize(String sensorId) {
        SensorState state = sensorStates.get(sensorId);
        if (state == null) return 0;
        long count = state.totalPacketCount.sum();
        return count == 0 ? 0 : (double) state.totalPayloadSize.sum() / count;
    }

    public double getTrafficAsymmetry(String sensorId) {
        SensorState state = sensorStates.get(sensorId);
        if (state == null) return 0;
        double in = state.inboundBytes.sum();
        double out = state.outboundBytes.sum();
        if (out == 0) return in;
        return in / out;
    }

    public int getActiveFlowsCount(String sensorId) {
        SensorState state = sensorStates.get(sensorId);
        return state == null ? 0 : state.activeFlows.size();
    }

    public Map<String, Integer> getAndResetPortVariety(String sensorId) {
        Map<String, Integer> result = new HashMap<>();
        SensorState state = sensorStates.get(sensorId);
        if (state != null) {
            state.portVarietyMap.forEach((ip, ports) -> result.put(ip, ports.size()));
            state.portVarietyMap.clear();
        }
        return result;
    }

    public void resetAll(String sensorId) {
        SensorState state = sensorStates.get(sensorId);
        if (state != null) {
            state.synCount.set(0);
            state.icmpCount.set(0);
            state.totalPacketCount.reset();
            state.totalPayloadSize.reset();
            state.inboundBytes.reset();
            state.outboundBytes.reset();
            state.portVarietyMap.clear();
            state.activeFlows.clear();
        }
    }
}