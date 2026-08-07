package com.ids.ids_controller.api;

import com.ids.ids_controller.dto.SensorConfigDTO;
import com.ids.ids_controller.dto.TargetConfigDTO;
import com.ids.ids_controller.model.Incident;
import com.ids.ids_controller.model.SensorMetadata;
import com.ids.ids_controller.model.TargetMetadata;
import com.ids.ids_controller.service.AssetMetadataService;
import com.ids.ids_controller.service.BaselineService;
import com.ids.ids_controller.service.IncidentService;
import com.ids.ids_controller.service.StatisticsAggregator;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/dashboard")
public class DashboardController {

    private final AssetMetadataService assetMetadataService;
    private final BaselineService baselineService;
    private final StatisticsAggregator aggregator;
    private final IncidentService incidentService;

    public DashboardController(BaselineService baselineService, StatisticsAggregator aggregator, IncidentService incidentService, AssetMetadataService assetMetadataService) {
        this.baselineService = baselineService;
        this.aggregator = aggregator;
        this.incidentService = incidentService;
        this.assetMetadataService = assetMetadataService;
    }

    @GetMapping
    public String index(Model model) {
        return "index";
    }

    // Nowa struktura: Map<SensorID, Map<NazwaMetryki, Wartosc>>
    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @ResponseBody
    public Flux<Map<String, Map<String, Double>>> streamMetrics() {
        return Flux.interval(Duration.ofSeconds(1))
                .map(sequence -> {
                    Map<String, Map<String, Double>> allSensorsData = new HashMap<>();
                    // Pobieramy metryki niezależnie dla każdej wykrytej sondy
                    for (String sensorId : incidentService.getActiveSensors()) {
                        allSensorsData.put(sensorId, aggregator.getCurrentMetrics(sensorId));
                    }
                    return allSensorsData;
                })
                .subscribeOn(Schedulers.boundedElastic());
    }

    @GetMapping(value = "/incidents/{id}/pcap", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    @ResponseBody
    public Mono<ResponseEntity<byte[]>> downloadPcap(@PathVariable String id) {
        return Mono.justOrEmpty(incidentService.getIncident(id))
                .map(incident -> ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"incident_" + id.substring(0,8) + ".pcap\"")
                        .body(incident.pcapData()))
                .defaultIfEmpty(ResponseEntity.notFound().build())
                .subscribeOn(Schedulers.boundedElastic());
    }

    @GetMapping("/incidents")
    @ResponseBody
    public Flux<Incident> getIncidentsList() {
        return Flux.fromIterable(incidentService.getAllIncidents())
                .subscribeOn(Schedulers.boundedElastic());
    }

    @GetMapping(value = "/incidents/{id}/json", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Mono<ResponseEntity<String>> downloadIdmefJson(@PathVariable String id) {
        return Mono.justOrEmpty(incidentService.getIncident(id))
                .map(incident -> ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"idmef_" + id.substring(0,8) + ".json\"")
                        .body(incident.idmefJson()))
                .defaultIfEmpty(ResponseEntity.notFound().build())
                .subscribeOn(Schedulers.boundedElastic());
    }
    @GetMapping("/configuration/sensors")
    @ResponseBody
    public Flux<SensorConfigDTO> getConfigurableSensors() {
        return Flux.defer(() -> {
            List<SensorConfigDTO> dtos = new ArrayList<>();
            for (String sensorId : incidentService.getActiveSensors()) {
                SensorMetadata meta = assetMetadataService.getSensorMetadata(sensorId);
                dtos.add(new SensorConfigDTO(
                        sensorId,
                        (meta != null && meta.getName() != null) ? meta.getName() : "null",
                        (meta != null && meta.getHostname() != null) ? meta.getHostname() : "null",
                        (meta != null && meta.getModel() != null) ? meta.getModel() : "null",
                        (meta != null && meta.getLocation() != null) ? meta.getLocation() : "null"
                ));
            }
            return Flux.fromIterable(dtos);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    // Zapis metadanych sensora z formularza (Wywoływany przez JS Fetch API)
    @PostMapping("/configuration/sensors/{id}")
    @ResponseBody
    public Mono<ResponseEntity<String>> saveSensorMetadata(
            @PathVariable("id") String sensorId,
            @RequestBody SensorMetadata metadata) {

        return Mono.fromRunnable(() -> assetMetadataService.updateSensorMetadata(sensorId, metadata))
                .subscribeOn(Schedulers.boundedElastic())
                .thenReturn(ResponseEntity.ok("Zapisano metadane sensora"));
    }

    @GetMapping("/configuration/targets")
    @ResponseBody
    public Flux<TargetConfigDTO> getConfigurableTargets() {
        return Flux.defer(() -> {
            List<TargetConfigDTO> dtos = new ArrayList<>();
            // Zwracamy znane targety z wykrytych incydentów lub statycznej konfiguracji
            for (String targetIp : incidentService.getActiveTargets()) {
                TargetMetadata meta = assetMetadataService.getTargetMetadata(targetIp);
                dtos.add(new TargetConfigDTO(
                        targetIp,
                        (meta != null && meta.getName() != null) ? meta.getName() : "null",
                        (meta != null && meta.getHostname() != null) ? meta.getHostname() : "null",
                        (meta != null && meta.getLocation() != null) ? meta.getLocation() : "null"
                ));
            }
            return Flux.fromIterable(dtos);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    @PostMapping("/configuration/targets/{ip}")
    @ResponseBody
    public Mono<ResponseEntity<String>> saveTargetMetadata(
            @PathVariable("ip") String targetIp,
            @RequestBody TargetMetadata metadata) {

        return Mono.fromRunnable(() -> assetMetadataService.updateTargetMetadata(targetIp, metadata))
                .subscribeOn(Schedulers.boundedElastic())
                .thenReturn(ResponseEntity.ok("Zapisano metadane targetu"));
    }
}