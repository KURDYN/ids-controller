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

@Service
public class StatisticsAggregator {
    private static final Logger log = LoggerFactory.getLogger(StatisticsAggregator.class);

    private final FeatureExtractor featureExtractor;
    private final BaselineService baselineService;
    private final FuzzyService fuzzyService;
    private Disposable subscription; // Referencja do subskrypcji, by móc ją zamknąć

    public double lastProbability;
    public double zSyn;
    public double zIcmp;
    public double zAvgSize;
    public double zAsym;
    public double zFlows;
    public double zPortVar;

    public StatisticsAggregator(FeatureExtractor featureExtractor, BaselineService baselineService, FuzzyService fuzzyService) {
        this.featureExtractor = featureExtractor;
        this.baselineService = baselineService;
        this.fuzzyService = fuzzyService;
    }

    @PostConstruct
    public void init() {
        log.info("Inicjalizacja agregatora statystyk...");

        // Tworzymy strumień, który "tyka" co 1 sekundę
        this.subscription = Flux.interval(Duration.ofSeconds(1))
                .publishOn(Schedulers.parallel())
                .map(tick -> captureSnapshot())
                .doOnNext(this::logSnapshot)
                .subscribe(
                        tick -> {}, // OnNext
                        error -> log.error("Błąd w strumieniu agregatora: ", error)
                );
    }

    private NetworkSnapshot captureSnapshot() {
        int syns = featureExtractor.getAndResetSynCount();
        int icmps = featureExtractor.getAndResetIcmpCount();
        double avgSize = featureExtractor.getAvgPacketSize();
        double asymmetry = featureExtractor.getTrafficAsymmetry();
        int flows = featureExtractor.getActiveFlowsCount();

        Map<String, Integer> portMap = featureExtractor.getAndResetPortVariety();
        int globalPortDiversity = portMap.values().stream().mapToInt(Integer::intValue).sum();

        NetworkSnapshot snapshot = new NetworkSnapshot(
                syns, icmps, avgSize, asymmetry, flows, globalPortDiversity
        );

        featureExtractor.resetAll();

        return snapshot;
    }

    private void logSnapshot(NetworkSnapshot s) {
        this.zSyn = baselineService.calculateZScore("SYNS_PER_SEC", s.syns);
        this.zIcmp = baselineService.calculateZScore("ICMPS_PER_SEC", s.icmps);
        this.zAvgSize = baselineService.calculateZScore("AVG_PACKET_SIZE", s.avgPacketSize);
        this.zAsym = baselineService.calculateZScore("TRAFFIC_ASYMMETRY", s.asymmetry);
        this.zFlows = baselineService.calculateZScore("ACTIVE_FLOWS", s.flows);
        this.zPortVar = baselineService.calculateZScore("GLOBAL_PORT_DIVERSITY", s.portDiversity);


        log.info("--- NETWORK SNAPSHOT (REACTIVE) ---");
        log.info("Liczników SYN:   {} pkt/s,     Z: {}", s.syns(), zSyn);
        log.info("Liczników ICMP:  {} pkt/s,     Z: {}", s.icmps(), zIcmp);
        log.info("Śr. rozm. pkt:   {} bytes,     Z: {}", String.format("%.2f", s.avgPacketSize()), zAvgSize);
        log.info("Asymetria (I/O): {},           Z: {}", String.format("%.2f", s.asymmetry()), zAsym);
        log.info("Aktywne Flowy:   {},           Z: {}", s.flows(), zFlows);
        log.info("Ilość unikalnych portów:   {}, Z: {}", s.portDiversity, zPortVar);
        log.info("------------------------------------");

        this.lastProbability = fuzzyService.analyze(zSyn, zIcmp, zAvgSize, zAsym, zFlows, zPortVar);

        log.info("--- ANALIZA ZAGROŻEŃ ---");
        log.info("Prawdopodobieństwo anomalii: {}%", String.format("%.2f", this.lastProbability));

        if (this.lastProbability > 70) {
            log.error("!!! WYKRYTO POWAŻNĄ ANOMALIĘ !!!");
        }

        baselineService.addObservation("SYNS_PER_SEC", s.syns, this.lastProbability);
        baselineService.addObservation("ICMPS_PER_SEC", s.icmps, this.lastProbability);
        baselineService.addObservation("AVG_PACKET_SIZE", s.avgPacketSize, this.lastProbability);
        baselineService.addObservation("TRAFFIC_ASYMMETRY", s.asymmetry, this.lastProbability);
        baselineService.addObservation("ACTIVE_FLOWS", s.flows, this.lastProbability);
        baselineService.addObservation("GLOBAL_PORT_DIVERSITY", s.portDiversity, this.lastProbability);
    }

    public Map<String, Double> getCurrentMetrics() {
        Map<String, Double> metrics = new HashMap<>();
        metrics.put("SYNS_PER_SEC", this.zSyn);
        metrics.put("ICMPS_PER_SEC", this.zIcmp);
        metrics.put("AVG_PACKET_SIZE", this.zAvgSize);
        metrics.put("TRAFFIC_ASYMMETRY", this.zAsym);
        metrics.put("ACTIVE_FLOWS", this.zFlows);
        metrics.put("GLOBAL_PORT_DIVERSITY", this.zPortVar);
        metrics.put("anomalyProbability", this.lastProbability);

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