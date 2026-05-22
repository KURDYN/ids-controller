package com.ids.ids_controller.service;

import com.ids.ids_controller.model.Incident;
import com.ids.ids_controller.model.SensorContext;
import org.springframework.stereotype.Service;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class IncidentService {

    // Mapa przechowująca osobny kontekst sieciowy dla każdego sensora
    private final Map<String, SensorContext> sensorContexts = new ConcurrentHashMap<>();

    // Repozytorium incydentów (warto rozważyć kluczowanie sensorId + incidentId)
    private final Map<String, Incident> incidentRepository = new ConcurrentHashMap<>();

    // Metoda pomocnicza pobierająca lub tworząca kontekst dla nowej sondy w locie
    private SensorContext getOrCreateContext(String sensorId) {
        return sensorContexts.computeIfAbsent(sensorId, SensorContext::new);
    }

    public void setGlobalHeader(String sensorId, byte[] header) {
        getOrCreateContext(sensorId).setGlobalHeader(header);
    }

    // Wywoływane teraz z przekazaniem ID sensora
    public void registerPacket(String sensorId, byte[] packetWithHeader) {
        getOrCreateContext(sensorId).registerPacket(packetWithHeader);
    }

    public void handleAttackDetection(String sensorId, double probability, String description) {
        getOrCreateContext(sensorId).startAttackOrUpdate(probability);
    }

    public void endAttack(String sensorId) {
        SensorContext context = sensorContexts.get(sensorId);
        if (context != null) {
            Incident completedIncident = context.endAttack();
            if (completedIncident != null) {
                incidentRepository.put(completedIncident.getId(), completedIncident);
            }
        }
    }

    // Metody dla kontrolera (UI), pozwalające filtrować dane na zakładki
    public Collection<Incident> getIncidentsBySensor(String sensorId) {
        return incidentRepository.values().stream()
                .filter(inc -> sensorId.equals(inc.getSensorId()))
                .collect(Collectors.toList());
    }

    public Set<String> getActiveSensors() {
        return sensorContexts.keySet();
    }

    public Incident getIncident(String id) {
        return incidentRepository.get(id);
    }

    public Collection<Incident> getAllIncidents() {
        return incidentRepository.values();
    }
}