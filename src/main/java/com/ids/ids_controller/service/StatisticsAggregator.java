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
        double zAsym;
        double zFlows;
        double zPortVar;
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
        int syns = featureExtractor.getAndResetSynCount(sensorId);
        int icmps = featureExtractor.getAndResetIcmpCount(sensorId);
        double avgSize = featureExtractor.getAvgPacketSize(sensorId);
        double asymmetry = featureExtractor.getTrafficAsymmetry(sensorId);
        int flows = featureExtractor.getActiveFlowsCount(sensorId);

        Map<String, Integer> portMap = featureExtractor.getAndResetPortVariety(sensorId);
        int globalPortDiversity = portMap.values().stream().mapToInt(Integer::intValue).sum();

        NetworkSnapshot snapshot = new NetworkSnapshot(
                syns, icmps, avgSize, asymmetry, flows, globalPortDiversity
        );

        featureExtractor.resetAll(sensorId);

        return snapshot;
    }

    private void logSnapshot(NetworkSnapshot s, String sensorId) {
        SensorMetrics metrics = sensorMetricsMap.computeIfAbsent(sensorId, k -> new SensorMetrics());

        // Dynamiczny prefiks izoluje bazy statystyczne wewnątrz BaselineService
        String prefix = sensorId + ":";

        metrics.zSyn = baselineService.calculateZScore(prefix + "SYNS_PER_SEC", s.syns);
        metrics.zIcmp = baselineService.calculateZScore(prefix + "ICMPS_PER_SEC", s.icmps);
        metrics.zAvgSize = baselineService.calculateZScore(prefix + "AVG_PACKET_SIZE", s.avgPacketSize);
        metrics.zAsym = baselineService.calculateZScore(prefix + "TRAFFIC_ASYMMETRY", s.asymmetry);
        metrics.zFlows = baselineService.calculateZScore(prefix + "ACTIVE_FLOWS", s.flows);
        metrics.zPortVar = baselineService.calculateZScore(prefix + "GLOBAL_PORT_DIVERSITY", s.portDiversity);

        log.info("--- NETWORK SNAPSHOT (REACTIVE) - SENSOR: [{}] ---", sensorId);
        log.info("Liczników SYN:   {} pkt/s,     Z: {}", s.syns(), metrics.zSyn);
        log.info("Liczników ICMP:  {} pkt/s,     Z: {}", s.icmps(), metrics.zIcmp);
        log.info("Śr. rozm. pkt:   {} bytes,     Z: {}", String.format("%.2f", s.avgPacketSize()), metrics.zAvgSize);
        log.info("Asymetria (I/O): {},           Z: {}", String.format("%.2f", s.asymmetry()), metrics.zAsym);
        log.info("Aktywne Flowy:   {},           Z: {}", s.flows(), metrics.zFlows);
        log.info("Ilość unikalnych portów:   {}, Z: {}", s.portDiversity, metrics.zPortVar);
        log.info("------------------------------------");

        metrics.lastProbability = fuzzyService.analyze(metrics.zSyn, metrics.zIcmp, metrics.zAvgSize, metrics.zAsym, metrics.zFlows, metrics.zPortVar);

        log.info("--- ANALIZA ZAGROŻEŃ - SENSOR: [{}] ---", sensorId);
        log.info("Prawdopodobieństwo anomalii: {}%", String.format("%.2f", metrics.lastProbability));

        if (metrics.lastProbability > 60) {
            log.error("!!! WYKRYTO POWAŻNĄ ANOMALIĘ W SEGMENCIE: [{}] !!!", sensorId);
            incidentService.handleAttackDetection(sensorId, metrics.lastProbability, "ATAK");
        }
        else {
            incidentService.endAttack(sensorId);
        }

        baselineService.addObservation(prefix + "SYNS_PER_SEC", s.syns, metrics.lastProbability);
        baselineService.addObservation(prefix + "ICMPS_PER_SEC", s.icmps, metrics.lastProbability);
        baselineService.addObservation(prefix + "AVG_PACKET_SIZE", s.avgPacketSize, metrics.lastProbability);
        baselineService.addObservation(prefix + "TRAFFIC_ASYMMETRY", s.asymmetry, metrics.lastProbability);
        baselineService.addObservation(prefix + "ACTIVE_FLOWS", s.flows, metrics.lastProbability);
        baselineService.addObservation(prefix + "GLOBAL_PORT_DIVERSITY", s.portDiversity, metrics.lastProbability);
    }

    // Metoda przyjmuje teraz sensorId, aby kontroler/UI mógł pobrać metryki dla wybranej zakładki
    public Map<String, Double> getCurrentMetrics(String sensorId) {
        Map<String, Double> metrics = new HashMap<>();
        SensorMetrics sm = sensorMetricsMap.get(sensorId);

        if (sm != null) {
            metrics.put("SYNS_PER_SEC", sm.zSyn);
            metrics.put("ICMPS_PER_SEC", sm.zIcmp);
            metrics.put("AVG_PACKET_SIZE", sm.zAvgSize);
            metrics.put("TRAFFIC_ASYMMETRY", sm.zAsym);
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
            int syns,
            int icmps,
            double avgPacketSize,
            double asymmetry,
            int flows,
            int portDiversity
    ) {}
}