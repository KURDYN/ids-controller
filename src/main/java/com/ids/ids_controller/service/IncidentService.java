package com.ids.ids_controller.service;

import com.ids.ids_controller.model.Incident;
import org.springframework.stereotype.Service;
import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class IncidentService {

    private byte[] pcapGlobalHeader;

    // Pasywny bufor kołowy na pakiety
    private final Deque<byte[]> rollingPacketBuffer = new ConcurrentLinkedDeque<>();
    private final int MAX_ROLLING_SIZE = 2000;

    // Atomowy licznik rozmiaru bufora - zapewnia operację O(1) zamiast O(n)
    private final AtomicInteger currentBufferSize = new AtomicInteger(0);

    // Przechowalnia gotowych incydentów
    private final Map<String, Incident> incidentRepository = new ConcurrentHashMap<>();

    // volatile gwarantuje, że wszystkie wątki natychmiast zobaczą zmianę stanu ataku
    private volatile boolean isAttackOngoing = false;
    private ByteArrayOutputStream activeIncidentStream;
    private String currentIncidentId;
    private double currentMaxProb = 0.0;

    public void setGlobalHeader(byte[] header) {
        if (this.pcapGlobalHeader == null) {
            this.pcapGlobalHeader = header.clone();
        }
    }

    // Wywoływane przez PcapReceiver dla KAŻDEGO pakietu
    public void registerPacket(byte[] packetWithHeader) {
        if (isAttackOngoing) {
            // Blok synchronized chroni strumień przed równoległym zapisem i nagłym ustawieniem na null
            synchronized (this) {
                if (isAttackOngoing && activeIncidentStream != null) {
                    try {
                        activeIncidentStream.write(packetWithHeader);
                    } catch (Exception ignored) {}
                } else {
                    // W razie mikro-wyścigu na przełomie stanu, zabezpieczamy pakiet w buforze
                    pushToRollingBuffer(packetWithHeader);
                }
            }
        } else {
            pushToRollingBuffer(packetWithHeader);
        }
    }

    private void pushToRollingBuffer(byte[] packet) {
        rollingPacketBuffer.addLast(packet);
        // Bezpieczne i ekstremalnie szybkie sprawdzanie rozmiaru
        if (currentBufferSize.incrementAndGet() > MAX_ROLLING_SIZE) {
            if (rollingPacketBuffer.pollFirst() != null) {
                currentBufferSize.decrementAndGet();
            }
        }
    }

    // Wywoływane przez StatisticsAggregator, gdy prob > 70%
    public synchronized void handleAttackDetection(double probability, String description) {
        if (!isAttackOngoing) {
            isAttackOngoing = true;
            currentIncidentId = UUID.randomUUID().toString();
            currentMaxProb = probability;
            activeIncidentStream = new ByteArrayOutputStream();

            if (pcapGlobalHeader != null) {
                activeIncidentStream.writeBytes(pcapGlobalHeader);
            }

            // Opróżniamy bufor i aktualizujemy atomowy licznik
            while (!rollingPacketBuffer.isEmpty()) {
                byte[] pkt = rollingPacketBuffer.pollFirst();
                if (pkt != null) {
                    activeIncidentStream.writeBytes(pkt);
                    currentBufferSize.decrementAndGet();
                }
            }
        } else {
            if (probability > currentMaxProb) currentMaxProb = probability;
        }
    }

    // Wywoływane, gdy opadną emocje (prob < 30% i minęło okno czasowe)
    public synchronized void endAttack() {
        if (isAttackOngoing && activeIncidentStream != null) {
            Incident incident = new Incident(
                    currentIncidentId,
                    Instant.now(),
                    "Wykryto anomalię sieciową (Z-Score Trigger)",
                    currentMaxProb,
                    activeIncidentStream.toByteArray()
            );
            incidentRepository.put(currentIncidentId, incident);

            // Czyszczenie stanu - najpierw flaga, potem zamknięcie strumienia
            isAttackOngoing = false;
            activeIncidentStream = null;
        }
    }

    public Collection<Incident> getAllIncidents() {
        return incidentRepository.values();
    }

    public Optional<Incident> getIncident(String id) {
        return Optional.ofNullable(incidentRepository.get(id));
    }
}