package com.ids.ids_controller.service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.Disposable;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class StatisticsAggregator {
    private static final Logger log = LoggerFactory.getLogger(StatisticsAggregator.class);

    private final FeatureExtractor featureExtractor;
    private final BaselineService baselineService;
    private final FuzzyService fuzzyService;
    private final IncidentService incidentService;
    private Disposable subscription;

    // Mapa przechowująca metryki i wyniki analizy osobno dla każdego sensora
    private final Map<String, SensorMetrics> sensorMetricsMap = new ConcurrentHashMap<>();

    private static class SensorMetrics {
        double lastProbability;
        double zSyn;
        double zIcmp;
        double zAvgSize;
        double zTrafficVolume;
        double zFlows;
        double zPortVar;
    }

    private volatile double attackThreshold = 60.0;

    public double getAttackThreshold() {
        return attackThreshold;
    }

    public void setAttackThreshold(double attackThreshold) {
        this.attackThreshold = attackThreshold;
        log.info("Zmieniono próg detekcji ataku na: {}%", attackThreshold);
    }

    public StatisticsAggregator(FeatureExtractor featureExtractor, BaselineService baselineService, FuzzyService fuzzyService, IncidentService incidentService) {
        this.featureExtractor = featureExtractor;
        this.baselineService = baselineService;
        this.fuzzyService = fuzzyService;
        this.incidentService = incidentService;
    }

    @PostConstruct
    public void init() {
        log.info("Inicjalizacja agregatora statystyk...");

        // Co sekundę iterujemy po wszystkich aktywnych sensorach zarejestrowanych w systemie
        this.subscription = Flux.interval(Duration.ofSeconds(1))
                .publishOn(Schedulers.parallel())
                .doOnNext(tick -> {
                    for (String sensorId : incidentService.getActiveSensors()) {
                        NetworkSnapshot snapshot = captureSnapshot(sensorId);
                        logSnapshot(snapshot, sensorId);
                    }
                })
                .subscribe(
                        tick -> {},
                        error -> log.error("Błąd w strumieniu agregatora: ", error)
                );
    }

    // Pobieranie danych z ekstraktora na podstawie konkretnego sensorId
    private NetworkSnapshot captureSnapshot(String sensorId) {

        FeatureExtractor.FeatureWindow window =
                featureExtractor.drainWindow(sensorId);

        return new NetworkSnapshot(
                window.synCount(),
                window.icmpCount(),
                window.averageFrameSizeBytes(),
                window.trafficVolumeBytesPerSecond(),
                window.uniqueFlowCount(),
                window.portDiversity()
        );
    }

    private void logSnapshot(NetworkSnapshot s, String sensorId) {
        SensorMetrics metrics = sensorMetricsMap.computeIfAbsent(sensorId, k -> new SensorMetrics());

        // Dynamiczny prefiks izoluje bazy statystyczne wewnątrz BaselineService
        String prefix = sensorId + ":";

        metrics.zSyn = baselineService.calculateZScore(prefix + "SYNS_PER_SEC", s.syns);
        metrics.zIcmp = baselineService.calculateZScore(prefix + "ICMPS_PER_SEC", s.icmps);
        metrics.zAvgSize = baselineService.calculateZScore(prefix + "AVG_PACKET_SIZE", s.avgPacketSize);
        metrics.zTrafficVolume = baselineService.calculateZScore(prefix + "TRAFFIC_VOLUME_BYTES_PER_SEC", s.trafficVolumeBytesPerSecond);
        metrics.zFlows = baselineService.calculateZScore(prefix + "ACTIVE_FLOWS", s.flows);
        metrics.zPortVar = baselineService.calculateZScore(prefix + "GLOBAL_PORT_DIVERSITY", s.portDiversity);

        log.info("--- NETWORK SNAPSHOT - SENSOR: [{}] ---", sensorId);
        log.info("Liczników SYN:   {} pkt/s,     Z: {}", s.syns(), metrics.zSyn);
        log.info("Liczników ICMP:  {} pkt/s,     Z: {}", s.icmps(), metrics.zIcmp);
        log.info("Śr. rozm. pkt:   {} bytes,     Z: {}", String.format("%.2f", s.avgPacketSize()), metrics.zAvgSize);
        log.info("Wolumen ruchu:   {} B/s,       Z: {}", String.format("%.2f", s.trafficVolumeBytesPerSecond), metrics.zTrafficVolume);
        log.info("Aktywne Flowy:   {},           Z: {}", s.flows(), metrics.zFlows);
        log.info("Ilość unikalnych portów:   {}, Z: {}", s.portDiversity, metrics.zPortVar);
        log.info("------------------------------------");

        //metrics.lastProbability = fuzzyService.analyze(metrics.zSyn, metrics.zIcmp, metrics.zAvgSize, metrics.zAsym, metrics.zFlows, metrics.zPortVar);

        log.info("--- ANALIZA ZAGROŻEŃ - SENSOR: [{}] ---", sensorId);
        log.info("Prawdopodobieństwo anomalii: {}%", String.format("%.2f", metrics.lastProbability));

        double currentThreshold = attackThreshold;
        boolean attackDetected = metrics.lastProbability > currentThreshold;

        if (attackDetected) {
            log.error("!!! WYKRYTO POWAŻNĄ ANOMALIĘ W SEGMENCIE: [{}] !!!", sensorId);
            incidentService.handleAttackDetection(sensorId, metrics.lastProbability, "ATAK");
        } else {
            incidentService.endAttack(sensorId);
        }

        baselineService.addObservation(prefix + "SYNS_PER_SEC", s.syns, metrics.zSyn, attackDetected);
        baselineService.addObservation(prefix + "ICMPS_PER_SEC", s.icmps, metrics.zIcmp, attackDetected);
        baselineService.addObservation(prefix + "AVG_PACKET_SIZE", s.avgPacketSize, metrics.zAvgSize, attackDetected);
        baselineService.addObservation(prefix + "TRAFFIC_VOLUME_BYTES_PER_SEC", s.trafficVolumeBytesPerSecond, metrics.zTrafficVolume, attackDetected);
        baselineService.addObservation(prefix + "ACTIVE_FLOWS", s.flows, metrics.zFlows, attackDetected);
        baselineService.addObservation(prefix + "GLOBAL_PORT_DIVERSITY", s.portDiversity, metrics.zPortVar, attackDetected);
        baselineService.recordSensorState(sensorId, metrics.lastProbability);
    }

    // Metoda przyjmuje teraz sensorId, aby kontroler/UI mógł pobrać metryki dla wybranej zakładki
    public Map<String, Double> getCurrentMetrics(String sensorId) {
        Map<String, Double> metrics = new HashMap<>();
        SensorMetrics sm = sensorMetricsMap.get(sensorId);

        if (sm != null) {
            metrics.put("SYNS_PER_SEC", sm.zSyn);
            metrics.put("ICMPS_PER_SEC", sm.zIcmp);
            metrics.put("AVG_PACKET_SIZE", sm.zAvgSize);
            metrics.put("TRAFFIC_VOLUME_BYTES_PER_SEC", sm.zTrafficVolume);
            metrics.put("ACTIVE_FLOWS", sm.zFlows);
            metrics.put("GLOBAL_PORT_DIVERSITY", sm.zPortVar);
            metrics.put("anomalyProbability", sm.lastProbability);
        }

        return metrics;
    }

    @PreDestroy
    public void cleanup() {
        if (subscription != null) {
            subscription.dispose();
            log.info("Strumień agregatora został zatrzymany.");
        }
    }

    private record NetworkSnapshot(
            long syns,
            long icmps,
            double avgPacketSize,
            double trafficVolumeBytesPerSecond,
            int flows,
            int portDiversity
    ) {}
}