package com.ids.ids_controller.api;

import com.ids.ids_controller.dto.SensorConfigDTO;
import com.ids.ids_controller.dto.TargetConfigDTO;
import com.ids.ids_controller.model.*;
import com.ids.ids_controller.service.AssetMetadataService;
import com.ids.ids_controller.service.BaselineService;
import com.ids.ids_controller.service.IncidentService;
import com.ids.ids_controller.service.StatisticsAggregator;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.codec.multipart.FilePart;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;
import tools.jackson.databind.ObjectMapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
    private final ObjectMapper objectMapper;

    public DashboardController(BaselineService baselineService, StatisticsAggregator aggregator, IncidentService incidentService, AssetMetadataService assetMetadataService, ObjectMapper objectMapper) {
        this.baselineService = baselineService;
        this.aggregator = aggregator;
        this.incidentService = incidentService;
        this.assetMetadataService = assetMetadataService;
        this.objectMapper = objectMapper;
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

    @GetMapping(value = "/configuration/export", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Mono<ResponseEntity<FullAssetMetadata>> exportConfiguration() {
        return Mono.fromSupplier(() -> ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"asset_config.json\"")
                        .body(assetMetadataService.getFullConfiguration())) // Wymaga dodania gettera w AssetMetadataService
                .subscribeOn(Schedulers.boundedElastic());
    }

    @PostMapping(value = "/configuration/import", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @ResponseBody
    public Mono<ResponseEntity<String>> importConfiguration(@RequestPart("file") FilePart filePart) {
        return filePart.content()
                .map(dataBuffer -> {
                    byte[] bytes = new byte[dataBuffer.readableByteCount()];
                    dataBuffer.read(bytes);
                    DataBufferUtils.release(dataBuffer);
                    return bytes;
                })
                .reduce(new ByteArrayOutputStream(), (baos, bytes) -> {
                    try {
                        baos.write(bytes);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                    return baos;
                })
                .map(baos -> baos.toByteArray())
                .publishOn(Schedulers.boundedElastic())
                .flatMap(bytes -> {
                    try {
                        FullAssetMetadata newConfig = objectMapper.readValue(bytes, FullAssetMetadata.class);
                        assetMetadataService.importFullConfiguration(newConfig); // Wymaga metody w AssetMetadataService
                        return Mono.just(ResponseEntity.ok("Import zakończony pomyślnie."));
                    } catch (Exception e) {
                        return Mono.just(ResponseEntity.badRequest().body("Błąd podczas parsowania pliku JSON: " + e.getMessage()));
                    }
                });
    }

    // --- KONFIGURACJA SIEM TARGETS ---

    @GetMapping("/configuration/siem")
    @ResponseBody
    public Flux<SiemTargetMetadata> getSiemTargets() {
        return Flux.defer(() -> Flux.fromIterable(assetMetadataService.getSiemTargets()))
                .subscribeOn(Schedulers.boundedElastic());
    }

    @PostMapping("/configuration/siem")
    @ResponseBody
    public Mono<ResponseEntity<String>> saveSiemTarget(@RequestBody SiemTargetMetadata target) {
        return Mono.fromRunnable(() -> assetMetadataService.addOrUpdateSiemTarget(target))
                .subscribeOn(Schedulers.boundedElastic())
                .thenReturn(ResponseEntity.ok("Zapisano konfigurację celu SIEM"));
    }

    @DeleteMapping("/configuration/siem/{id}")
    @ResponseBody
    public Mono<ResponseEntity<String>> deleteSiemTarget(@PathVariable("id") String id) {
        return Mono.fromRunnable(() -> assetMetadataService.deleteSiemTarget(id))
                .subscribeOn(Schedulers.boundedElastic())
                .thenReturn(ResponseEntity.ok("Usunięto cel SIEM"));
    }
}