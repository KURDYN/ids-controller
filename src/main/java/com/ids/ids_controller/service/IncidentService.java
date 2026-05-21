package com.ids.ids_controller.service;

import com.ids.ids_controller.model.Incident;
import org.springframework.stereotype.Service;
import java.io.ByteArrayOutputStream;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

@Service
public class IncidentService {

    private byte[] pcapGlobalHeader;
    // Pasywny bufor kołowy na pakiety (trzymamy max 2000 ostatnich pakietów)
    private final Deque<byte[]> rollingPacketBuffer = new ConcurrentLinkedDeque<>();
    private final int MAX_ROLLING_SIZE = 2000;

    // Przechowalnia gotowych incydentów
    private final Map<String, Incident> incidentRepository = new ConcurrentHashMap<>();

    // Flaga stanu ataku i aktywny strumień zapisu
    private boolean isAttackOngoing = false;
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
            // Trwa atak -> zapisujemy bezpośrednio do pliku incydentu
            try {
                activeIncidentStream.write(packetWithHeader);
            } catch (Exception ignored) {}
        } else {
            // Ruch normalny -> rotujemy w buforze pamięci podręcznej
            rollingPacketBuffer.addLast(packetWithHeader);
            if (rollingPacketBuffer.size() > MAX_ROLLING_SIZE) {
                rollingPacketBuffer.pollFirst();
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

            // KROK KLUCZOWY: Wpisujemy nagłówek globalny PCAP
            if (pcapGlobalHeader != null) {
                activeIncidentStream.writeBytes(pcapGlobalHeader);
            }

            // Przepychamy pakiety z bufora kołowego (kontekst sprzed ataku)
            while (!rollingPacketBuffer.isEmpty()) {
                byte[] pkt = rollingPacketBuffer.pollFirst();
                if (pkt != null) activeIncidentStream.writeBytes(pkt);
            }
        } else {
            if (probability > currentMaxProb) currentMaxProb = probability;
        }
    }

    // Wywoływane, gdy opadną emocje (prob < 30% i minęło okno czasowe)
    public synchronized void endAttack() {
        if (isAttackOngoing && activeIncidentStream != null) {
            isAttackOngoing = false;
            Incident incident = new Incident(
                    currentIncidentId,
                    Instant.now(),
                    "Wykryto anomalię sieciową (Z-Score Trigger)",
                    currentMaxProb,
                    activeIncidentStream.toByteArray()
            );
            incidentRepository.put(currentIncidentId, incident);
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
