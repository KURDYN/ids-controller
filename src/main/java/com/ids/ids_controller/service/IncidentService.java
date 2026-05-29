package com.ids.ids_controller.service;

import com.ids.ids_controller.model.Incident;
import com.ids.ids_controller.model.SensorContext;
import org.idmefv2.IDMEFException;
import org.idmefv2.IDMEFValidator;
import org.idmefv2.IDMEFObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.scheduler.Schedulers;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class IncidentService {
    private static final Logger log = LoggerFactory.getLogger(BaselineService.class);

    // Mapa przechowująca osobny kontekst sieciowy dla każdego sensora
    private final Map<String, SensorContext> sensorContexts = new ConcurrentHashMap<>();

    // Repozytorium incydentów (warto rozważyć kluczowanie sensorId + incidentId)
    private final Map<String, Incident> incidentRepository = new ConcurrentHashMap<>();

    private final WebClient siemClient = WebClient.create("http://172.16.0.99:4690");
    private final IDMEFValidator idmefValidator = new IDMEFValidator();

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
                CompletableFuture.runAsync(() -> {
                    try {
                        String idmefJson = buildAndValidateIdmef(completedIncident);

                        Incident finalIncident = new Incident(
                                completedIncident.id(),
                                completedIncident.sensorId(),
                                completedIncident.timestamp(),
                                completedIncident.description(),
                                completedIncident.maxProbability(),
                                completedIncident.pcapData(),
                                idmefJson
                        );

                        // POPRAWKA: Zapisujemy finalIncident (zawierający wygenerowany JSON), a nie completedIncident
                        incidentRepository.put(finalIncident.id(), finalIncident);

                        pushAlertToConcerto(idmefJson, finalIncident.id());
                    } catch (Exception e) {
                        log.error("Błąd podczas asynchronicznego przetwarzania końca ataku dla sensora {}: {}", sensorId, e.getMessage());
                    }
                });
            }
        }
    }

    private String buildAndValidateIdmef(Incident incident) {
        try {
            IDMEFObject msg = new IDMEFObject();
            msg.put("Version", "2.0.3");
            msg.put("ID", incident.id());

            String isoTimestamp = DateTimeFormatter.ISO_INSTANT
                    .format(incident.timestamp().atOffset(ZoneOffset.UTC));
            msg.put("CreateTime", isoTimestamp);
            msg.put("StartTime", isoTimestamp);
            msg.put("Description", incident.description() != null ? incident.description() : "Wykryto anomalię sieciową Z-Score");
            msg.put("Priority", incident.maxProbability() > 85.0 ? "High" : "Medium");
            msg.put("Category", new String[]{"Attempt.Login"});

            IDMEFObject analyzer = new IDMEFObject();
            analyzer.put("IP", "127.0.0.1");
            analyzer.put("Name", "IDS-Controller");
            analyzer.put("Type", "Cyber");
            analyzer.put("Model", "Fuzzy-ZScore-Engine 1.0");
            analyzer.put("Category", new String[]{"IDS"});
            analyzer.put("Data", new String[]{"Netflow"});
            analyzer.put("Method", new String[]{"Statistical"});
            msg.put("Analyzer", analyzer);

            IDMEFObject sensor = new IDMEFObject();
            sensor.put("IP", incident.getSensorId());
            sensor.put("Name", "Probe-Agent");
            sensor.put("Model", "PcapReceiver-Hook");

            List<IDMEFObject> sensorList = new ArrayList<>();
            sensorList.add(sensor);
            msg.put("Sensor", sensorList);

            idmefValidator.validate(msg);

            return new String(msg.serialize());
        } catch (IDMEFException e) {
            log.error("Błąd walidacji schematu IDMEFv2 dla incydentu {}: {}", incident.id(), e.getMessage());
            return "{\"error\": \"Invalid IDMEFv2 structure\"}";
        } catch (Exception e) {
            log.error("Błąd podczas serializacji wiadomości IDMEFv2: {}", e.getMessage());
            return "{}";
        }
    }

    private void pushAlertToConcerto(String jsonPayload, String incidentId) {
        siemClient.post()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(jsonPayload)
                .retrieve()
                .toBodilessEntity()
                .subscribeOn(Schedulers.boundedElastic())
                .subscribe(
                        response -> log.info("Alert IDMEFv2 dla incydentu [{}] został pomyślnie wysłany do Concerto SIEM.", incidentId),
                        error -> log.error("Nie udało się przesłać alertu IDMEFv2 do Concerto SIEM: {}", error.getMessage())
                );
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