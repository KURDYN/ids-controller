package com.ids.ids_controller.service;

import com.ids.ids_controller.model.Incident;
import com.ids.ids_controller.model.SensorContext;
import com.ids.ids_controller.model.SensorMetadata;
import com.ids.ids_controller.model.TargetMetadata;
import com.ids.ids_controller.model.SiemTargetMetadata;
import org.idmefv2.IDMEFException;
import org.idmefv2.IDMEFValidator;
import org.idmefv2.IDMEFObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;

import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
public class IncidentService {
    private static final Logger log = LoggerFactory.getLogger(IncidentService.class);

    private final Map<String, SensorContext> sensorContexts = new ConcurrentHashMap<>();
    private final Map<String, Incident> incidentRepository = new ConcurrentHashMap<>();

    private final AssetMetadataService assetMetadataService;
    private final FeatureExtractor featureExtractor;

    private final IDMEFValidator idmefValidator = new IDMEFValidator();

    public IncidentService(AssetMetadataService assetMetadataService,
                           FeatureExtractor featureExtractor) {
        this.assetMetadataService = assetMetadataService;
        this.featureExtractor = featureExtractor;
    }

    private SensorContext getOrCreateContext(String sensorId) {
        return sensorContexts.computeIfAbsent(sensorId, SensorContext::new);
    }

    public void setGlobalHeader(String sensorId, byte[] header) {
        getOrCreateContext(sensorId).setGlobalHeader(header);
    }

    public void registerPacket(String sensorId, byte[] packetWithHeader) {
        getOrCreateContext(sensorId).registerPacket(packetWithHeader);
    }

    public void handleAttackDetection(String sensorId, double probability, String description) {
        getOrCreateContext(sensorId).startAttackOrUpdate(probability);
    }

    public void endAttack(String sensorId) {
        SensorContext context = sensorContexts.get(sensorId);
        if (context != null) {
            String targetIp = featureExtractor.getDetectedTargetIp(sensorId);
            List<String> sourceIps = featureExtractor.getDetectedSourceIps(sensorId);

            Incident completedIncident = context.endAttack(targetIp, sourceIps);
            if (completedIncident != null) {
                CompletableFuture.runAsync(() -> {
                    try {
                        String idmefJson = buildAndValidateIdmef(completedIncident);

                        Incident finalIncident = new Incident(
                                completedIncident.id(),
                                completedIncident.sensorId(),
                                completedIncident.targetIp(),
                                completedIncident.sourceIps(),
                                completedIncident.timestamp(),
                                completedIncident.description(),
                                completedIncident.maxProbability(),
                                completedIncident.pcapData(),
                                idmefJson
                        );

                        incidentRepository.put(finalIncident.id(), finalIncident);

                        // Broadcast do wszystkich skonfigurowanych odbiorców SIEM
                        broadcastAlertToSiems(idmefJson, finalIncident.id());
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

            // ANALYZER
            IDMEFObject analyzer = new IDMEFObject();
            analyzer.put("IP", "127.0.0.1");
            analyzer.put("Name", "IDS-Controller");
            analyzer.put("Type", "Cyber");
            analyzer.put("Model", "Fuzzy-ZScore-Engine 1.0");
            analyzer.put("Category", new String[]{"IDS"});
            analyzer.put("Data", new String[]{"Netflow"});
            analyzer.put("Method", new String[]{"Statistical"});
            msg.put("Analyzer", analyzer);

            // SENSOR
            SensorMetadata sensorMeta = assetMetadataService.getSensorMetadata(incident.getSensorId());

            IDMEFObject sensor = new IDMEFObject();
            sensor.put("IP", incident.getSensorId());
            sensor.put("Name", (sensorMeta != null && sensorMeta.getName() != null && !sensorMeta.getName().equals("null")) ? sensorMeta.getName() : "Probe-Agent-Generic");
            sensor.put("Hostname", (sensorMeta != null && sensorMeta.getHostname() != null && !sensorMeta.getHostname().equals("null")) ? sensorMeta.getHostname() : "unknown-host");
            sensor.put("Model", (sensorMeta != null && sensorMeta.getModel() != null && !sensorMeta.getModel().equals("null")) ? sensorMeta.getModel() : "PcapReceiver-Hook");
            sensor.put("Location", (sensorMeta != null && sensorMeta.getLocation() != null && !sensorMeta.getLocation().equals("null")) ? sensorMeta.getLocation() : "Default DC");

            List<IDMEFObject> sensorList = new ArrayList<>();
            sensorList.add(sensor);
            msg.put("Sensor", sensorList);

            // TARGET
            String targetIp = incident.getTargetIp() != null ? incident.getTargetIp() : incident.getSensorId();
            assetMetadataService.registerTargetIfAbsent(targetIp);
            TargetMetadata targetMeta = assetMetadataService.getTargetMetadata(targetIp);

            IDMEFObject target = new IDMEFObject();
            target.put("IP", targetIp);
            if (targetMeta != null) {
                if (targetMeta.getName() != null && !targetMeta.getName().equals("null")) target.put("Name", targetMeta.getName());
                if (targetMeta.getHostname() != null && !targetMeta.getHostname().equals("null")) target.put("Hostname", targetMeta.getHostname());
                if (targetMeta.getLocation() != null && !targetMeta.getLocation().equals("null")) target.put("Location", targetMeta.getLocation());
            }

            List<IDMEFObject> targetList = new ArrayList<>();
            targetList.add(target);
            msg.put("Target", targetList);

            // SOURCE
            List<String> sources = incident.getSourceIps();
            if (sources != null && !sources.isEmpty()) {
                List<IDMEFObject> sourceList = new ArrayList<>();
                for (String srcIp : sources) {
                    IDMEFObject source = new IDMEFObject();
                    source.put("IP", srcIp);
                    sourceList.add(source);
                }
                msg.put("Source", sourceList);
            }

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

    /**
     * Równoległe wysyłanie alertu IDMEFv2 do wszystkich aktywnych odbiorców SIEM (Wariant Broadcast).
     */
    private void broadcastAlertToSiems(String jsonPayload, String incidentId) {
        List<SiemTargetMetadata> targets = assetMetadataService.getSiemTargets().stream()
                .filter(SiemTargetMetadata::isEnabled)
                .toList();

        if (targets.isEmpty()) {
            log.warn("Brak aktywnych celów SIEM. Alert dla incydentu [{}] nie został wysłany.", incidentId);
            return;
        }

        Flux.fromIterable(targets)
                .flatMap(target -> {
                    String url = String.format("http://%s:%d", target.getHost(), target.getPort());

                    // Tworzenie klienta w locie dla danego adresu URI
                    return WebClient.create(url)
                            .post()
                            .contentType(MediaType.APPLICATION_JSON)
                            .bodyValue(jsonPayload)
                            .retrieve()
                            .toBodilessEntity()
                            .doOnSuccess(response -> log.info("Alert IDMEFv2 [{}] pomyślnie wysłany do SIEM: {} ({})", incidentId, target.getName(), url))
                            .doOnError(error -> log.error("Błąd wysyłania alertu IDMEFv2 [{}] do SIEM: {} ({}): {}", incidentId, target.getName(), url, error.getMessage()))
                            .onErrorComplete();
                })
                .subscribeOn(Schedulers.boundedElastic())
                .subscribe();
    }

    public Collection<Incident> getIncidentsBySensor(String sensorId) {
        return incidentRepository.values().stream()
                .filter(inc -> sensorId.equals(inc.getSensorId()))
                .collect(Collectors.toList());
    }

    public Set<String> getActiveSensors() {
        return sensorContexts.keySet();
    }

    public Set<String> getActiveTargets() {
        return assetMetadataService.getActiveTargets();
    }

    public Incident getIncident(String id) {
        return incidentRepository.get(id);
    }

    public Collection<Incident> getAllIncidents() {
        return incidentRepository.values();
    }
}