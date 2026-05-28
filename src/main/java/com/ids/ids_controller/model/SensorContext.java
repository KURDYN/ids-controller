package com.ids.ids_controller.model;

import java.io.ByteArrayOutputStream;
import java.util.Deque;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;

public class SensorContext {
    private final String sensorId;
    private byte[] pcapGlobalHeader;

    private final Deque<byte[]> rollingPacketBuffer = new ConcurrentLinkedDeque<>();
    private final int MAX_ROLLING_SIZE = 2000;
    private final AtomicInteger currentBufferSize = new AtomicInteger(0);

    private volatile boolean isAttackOngoing = false;
    private ByteArrayOutputStream activeIncidentStream;
    private String currentIncidentId;
    private double currentMaxProb = 0.0;

    public SensorContext(String sensorId) {
        this.sensorId = sensorId;
    }

    // Gettery i metody operacji na stanie (wklejamy tu logikę z poprzedniego kroku, sprofilowaną pod jeden sensor)
    public synchronized void setGlobalHeader(byte[] header) {
        if (this.pcapGlobalHeader == null) {
            this.pcapGlobalHeader = header.clone();
        }
    }

    public void registerPacket(byte[] packetWithHeader) {
        if (isAttackOngoing) {
            synchronized (this) {
                if (isAttackOngoing && activeIncidentStream != null) {
                    try {
                        activeIncidentStream.write(packetWithHeader);
                    } catch (Exception ignored) {}
                } else {
                    pushToRollingBuffer(packetWithHeader);
                }
            }
        } else {
            pushToRollingBuffer(packetWithHeader);
        }
    }

    private void pushToRollingBuffer(byte[] packet) {
        rollingPacketBuffer.addLast(packet);
        if (currentBufferSize.incrementAndGet() > MAX_ROLLING_SIZE) {
            if (rollingPacketBuffer.pollFirst() != null) {
                currentBufferSize.decrementAndGet();
            }
        }
    }

    public synchronized Incident startAttackOrUpdate(double probability) {
        if (!isAttackOngoing) {
            isAttackOngoing = true;
            currentIncidentId = java.util.UUID.randomUUID().toString();
            currentMaxProb = probability;
            activeIncidentStream = new ByteArrayOutputStream();

            if (pcapGlobalHeader != null) {
                activeIncidentStream.writeBytes(pcapGlobalHeader);
            }

            while (!rollingPacketBuffer.isEmpty()) {
                byte[] pkt = rollingPacketBuffer.pollFirst();
                if (pkt != null) {
                    activeIncidentStream.writeBytes(pkt);
                    currentBufferSize.decrementAndGet();
                }
            }
            return null; // Atak się zaczął
        } else {
            if (probability > currentMaxProb) currentMaxProb = probability;
            return null;
        }
    }

    public synchronized Incident endAttack() {
        if (isAttackOngoing && activeIncidentStream != null) {
            Incident incident = new Incident(
                    currentIncidentId,
                    sensorId,
                    java.time.Instant.now(),
                    "Wykryto anomalię w segmencie: " + sensorId,
                    currentMaxProb,
                    activeIncidentStream.toByteArray(),
                    ""
            );

            isAttackOngoing = false;
            activeIncidentStream = null;
            return incident;
        }
        return null;
    }

    public boolean isAttackOngoing() { return isAttackOngoing; }
    public String getSensorId() { return sensorId; }
}