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

    // Flaga volatile gwarantuje natychmiastową widoczność zmian między wątkami bez blokowania
    private volatile boolean isAttackOngoing = false;

    // DEDYKOWANY LOCK: Oddziela wątek statystyk od wątku przechwytywania pakietów
    private final Object pcapLock = new Object();
    private ByteArrayOutputStream activeIncidentStream;

    // ZABEZPIECZENIE: Ograniczenie liczby pakietów per incydent, by flood nie zabił pamięci RAM
    private int attackPacketCount = 0;
    private final int MAX_ATTACK_PACKETS = 5000;

    private String currentIncidentId;
    private volatile double currentMaxProb = 0.0;

    public SensorContext(String sensorId) {
        this.sensorId = sensorId;
    }

    public void setGlobalHeader(byte[] header) {
        synchronized (pcapLock) {
            if (this.pcapGlobalHeader == null) {
                this.pcapGlobalHeader = header.clone();
            }
        }
    }

    public void registerPacket(byte[] packetWithHeader) {
        if (isAttackOngoing) {
            // Synchronizujemy tylko krytyczną sekcję zapisu do strumienia, a nie cały obiekt
            synchronized (pcapLock) {
                if (isAttackOngoing && activeIncidentStream != null) {
                    if (attackPacketCount < MAX_ATTACK_PACKETS) {
                        try {
                            activeIncidentStream.write(packetWithHeader);
                            attackPacketCount++;
                        } catch (Exception ignored) {}
                    }
                    // Powyżej limitu pakiety są bezpiecznie pomijane, zapobiegając GC Freeze
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

    public Incident startAttackOrUpdate(double probability) {
        if (probability > currentMaxProb) {
            currentMaxProb = probability;
        }

        if (!isAttackOngoing) {
            synchronized (pcapLock) {
                if (!isAttackOngoing) {
                    isAttackOngoing = true;
                    currentIncidentId = java.util.UUID.randomUUID().toString();
                    activeIncidentStream = new ByteArrayOutputStream();
                    attackPacketCount = 0;

                    if (pcapGlobalHeader != null) {
                        activeIncidentStream.writeBytes(pcapGlobalHeader);
                    }

                    while (!rollingPacketBuffer.isEmpty()) {
                        byte[] pkt = rollingPacketBuffer.pollFirst();
                        if (pkt != null) {
                            activeIncidentStream.writeBytes(pkt);
                            currentBufferSize.decrementAndGet();
                            attackPacketCount++;
                        }
                    }
                }
            }
        }
        return null;
    }

    public Incident endAttack() {
        if (isAttackOngoing) {
            synchronized (pcapLock) {
                if (isAttackOngoing && activeIncidentStream != null) {
                    // Pobieramy bezpieczną migawkę bajtów pod dedykowanym lockiem
                    byte[] pcapData = activeIncidentStream.toByteArray();

                    Incident incident = new Incident(
                            currentIncidentId,
                            sensorId,
                            java.time.Instant.now(),
                            "Wykryto anomalię w segmencie: " + sensorId,
                            currentMaxProb,
                            pcapData,
                            ""
                    );

                    // Resetowanie stanu powiązanego z pcap
                    isAttackOngoing = false;
                    activeIncidentStream = null;
                    attackPacketCount = 0;
                    currentMaxProb = 0.0;

                    return incident;
                }
            }
        }
        return null;
    }

    public boolean isAttackOngoing() { return isAttackOngoing; }
    public String getSensorId() { return sensorId; }
}