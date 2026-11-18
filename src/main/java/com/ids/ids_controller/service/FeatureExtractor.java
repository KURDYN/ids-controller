package com.ids.ids_controller.service;

import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.springframework.stereotype.Service;

import java.net.Inet4Address;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class FeatureExtractor {

    private static final Logger log =
            LoggerFactory.getLogger(FeatureExtractor.class);

    private static final int PCAP_RECEIVER_PORT = 9000;
    private static final int ICMP_ECHO_REQUEST_TYPE = 8;

    private static final int MAX_INCIDENT_SOURCE_IPS = 2048;

    private final Map<String, SensorState> sensorStates =
            new ConcurrentHashMap<>();

    private static class SensorState {
        long frameCount = 0;
        long totalFrameBytes = 0;
        long synCount = 0;
        long icmpCount = 0;

        final Set<String> activeFlows = new HashSet<>();
        final Map<String, Set<String>> portVarietyMap = new HashMap<>();
        long windowStartNanos = System.nanoTime();

        final LinkedHashSet<String> sourceIps = new LinkedHashSet<>();
        String lastTargetIp = null;
        boolean sourceIpsTruncated = false;
    }

    public record FeatureWindow(
            long synCount,
            long icmpCount,
            long frameCount,
            long totalFrameBytes,
            double averageFrameSizeBytes,
            double trafficVolumeBytesPerSecond,
            double durationSeconds,
            int uniqueFlowCount,
            int portDiversity
    ) {
        public static FeatureWindow empty() {
            return new FeatureWindow(0, 0, 0, 0, 0.0, 0.0, 0.0, 0, 0);
        }
    }

    public record IncidentEndpoints(String targetIp, List<String> sourceIps, boolean sourceIpsTruncated) {}

    public void extract(Packet packet, String sensorId) {
        if (packet == null) {
            return;
        }

        if (sensorId == null || sensorId.isBlank()) {
            throw new IllegalArgumentException("sensorId nie może być pusty");
        }

        if (isTrafficToController(packet)) {
            return;
        }

        if (!packet.contains(IpV4Packet.class)) {
            return;
        }

        IpV4Packet ipPacket = packet.get(IpV4Packet.class);

        Inet4Address srcAddress = ipPacket.getHeader().getSrcAddr();
        Inet4Address dstAddress = ipPacket.getHeader().getDstAddr();

        if (isInvalidSourceAddress(srcAddress)) {
            return;
        }

        String srcIp = srcAddress.getHostAddress();
        String dstIp = dstAddress.getHostAddress();

        int packetSize = packet.length();

        int protocolNumber = ipPacket.getHeader().getProtocol().value() & 0xFF;

        SensorState state = sensorStates.computeIfAbsent(sensorId, k -> new SensorState());

        synchronized (state) {
            state.frameCount++;
            state.totalFrameBytes += packetSize;

            registerIncidentEndpoints(state, srcIp, dstAddress, dstIp);

            String flowKey = buildFlowKey(packet, srcIp, dstIp, protocolNumber);

            state.activeFlows.add(flowKey);

            if (packet.contains(TcpPacket.class)) {
                TcpPacket tcp = packet.get(TcpPacket.class);
                int srcPort = tcp.getHeader().getSrcPort().valueAsInt();

                int dstPort = tcp.getHeader().getDstPort().valueAsInt();

                boolean syn = tcp.getHeader().getSyn();
                boolean ack = tcp.getHeader().getAck();

                if (syn && !ack) {
                    state.synCount++;
                    addDestinationPort(state, srcIp, "TCP", dstPort);
                }
            }

            if (packet.contains(UdpPacket.class)) {
                UdpPacket udp = packet.get(UdpPacket.class);
                int dstPort = udp.getHeader().getDstPort().valueAsInt();
                addDestinationPort(state, srcIp, "UDP", dstPort);
            }

            if (packet.contains(IcmpV4CommonPacket.class)) {
                IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
                if (icmp.getHeader().getType().value() == (byte) ICMP_ECHO_REQUEST_TYPE) {
                    state.icmpCount++;
                }
            }
        }
    }

    private boolean isInvalidSourceAddress(Inet4Address address) {

        return address.isLoopbackAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()
                || address.getHostAddress().equals("255.255.255.255");
    }

    private boolean isTrafficToController(Packet packet) {

        if (!packet.contains(TcpPacket.class)) {
            return false;
        }

        TcpPacket tcp = packet.get(TcpPacket.class);

        int srcPort = tcp.getHeader().getSrcPort().valueAsInt();
        int dstPort = tcp.getHeader().getDstPort().valueAsInt();
        return srcPort == PCAP_RECEIVER_PORT || dstPort == PCAP_RECEIVER_PORT;
    }

    // IDENTYFIKACJA PRZEPŁYWÓW
    private String buildFlowKey(Packet packet, String srcIp, String dstIp, int protocolNumber) {
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);

            int srcPort = tcp.getHeader().getSrcPort().valueAsInt();
            int dstPort = tcp.getHeader().getDstPort().valueAsInt();

            return buildBidirectionalFlowKey("TCP", srcIp + ":" + srcPort, dstIp + ":" + dstPort);
        }

        if (packet.contains(UdpPacket.class)) {
            UdpPacket udp = packet.get(UdpPacket.class);

            int srcPort = udp.getHeader().getSrcPort().valueAsInt();
            int dstPort = udp.getHeader().getDstPort().valueAsInt();

            return buildBidirectionalFlowKey("UDP", srcIp + ":" + srcPort, dstIp + ":" + dstPort);
        }

        if (packet.contains(IcmpV4CommonPacket.class)) {
            return buildBidirectionalFlowKey("ICMP", srcIp, dstIp);
        }

        return buildBidirectionalFlowKey("IP-" + protocolNumber, srcIp, dstIp);
    }

    private String buildBidirectionalFlowKey(String protocol, String endpointA, String endpointB) {
        if (endpointA.compareTo(endpointB) <= 0) {
            return protocol + "|" + endpointA + "|" + endpointB;
        }
        return protocol + "|" + endpointB + "|" + endpointA;
    }


    // PORT VARIETY
    private void addDestinationPort(SensorState state, String srcIp, String protocol, int dstPort) {
        String portIdentifier = protocol + ":" + dstPort;
        state.portVarietyMap.computeIfAbsent(srcIp, k -> new HashSet<>()).add(portIdentifier);
    }

    private void registerIncidentEndpoints(SensorState state, String srcIp, Inet4Address dstAddress, String dstIp) {
        if (!state.sourceIps.contains(srcIp)) {
            if (state.sourceIps.size() >= MAX_INCIDENT_SOURCE_IPS) {
                Iterator<String> iterator = state.sourceIps.iterator();

                if (iterator.hasNext()) {
                    iterator.next();
                    iterator.remove();
                }
                state.sourceIpsTruncated = true;
            }
            state.sourceIps.add(srcIp);
        }

        if (!dstAddress.isAnyLocalAddress()
                && !dstAddress.isLoopbackAddress()
                && !dstAddress.isMulticastAddress()
                && !dstIp.equals("255.255.255.255")) {

            state.lastTargetIp = dstIp;
        }
    }

    public IncidentEndpoints drainIncidentEndpoints(String sensorId) {
        SensorState state = sensorStates.get(sensorId);

        if (state == null) {
            return new IncidentEndpoints(null, Collections.emptyList(), false);
        }

        synchronized (state) {
            String targetIp = state.lastTargetIp;

            List<String> sourceIps = new ArrayList<>(state.sourceIps);

            boolean truncated = state.sourceIpsTruncated;

            state.lastTargetIp = null;
            state.sourceIps.clear();
            state.sourceIpsTruncated = false;

            return new IncidentEndpoints(targetIp, List.copyOf(sourceIps), truncated);
        }
    }

    public FeatureWindow drainWindow(String sensorId) {
        SensorState state = sensorStates.get(sensorId);

        if (state == null) {
            return FeatureWindow.empty();
        }

        synchronized (state) {
            long now = System.nanoTime();
            double elapsedSeconds = (now - state.windowStartNanos) / 1_000_000_000.0;

            if (elapsedSeconds <= 0.0 || !Double.isFinite(elapsedSeconds)) {
                elapsedSeconds = 0.000000001;
            }

            long frameCount = state.frameCount;
            long totalFrameBytes = state.totalFrameBytes;

            double averageFrameSize = frameCount == 0 ? 0.0 : (double) totalFrameBytes / frameCount;

            double trafficVolume = totalFrameBytes / elapsedSeconds;

            int uniqueFlowCount = state.activeFlows.size();

            int portDiversity = state.portVarietyMap.values().stream().mapToInt(Set::size).sum();

            FeatureWindow result = new FeatureWindow(
                    state.synCount,
                    state.icmpCount,
                    frameCount,
                    totalFrameBytes,
                    averageFrameSize,
                    trafficVolume,
                    elapsedSeconds,
                    uniqueFlowCount,
                    portDiversity
            );

            state.frameCount = 0;
            state.totalFrameBytes = 0;

            state.synCount = 0;
            state.icmpCount = 0;

            state.activeFlows.clear();
            state.portVarietyMap.clear();

            state.windowStartNanos = now;

            return result;
        }
    }
}
