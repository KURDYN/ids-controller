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
import java.util.Map;

@Service
public class StatisticsAggregator {
    private static final Logger log = LoggerFactory.getLogger(StatisticsAggregator.class);

    private final FeatureExtractor featureExtractor;
    private final BaselineService baselineService;
    private final FuzzyService fuzzyService;
    private Disposable subscription; // Referencja do subskrypcji, by móc ją zamknąć

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
        log.info("--- NETWORK SNAPSHOT (REACTIVE) ---");
        log.info("Liczników SYN:   {} pkt/s,     Z: {}", s.syns(), baselineService.calculateZScore("SYNS_PER_SEC", s.syns));
        log.info("Liczników ICMP:  {} pkt/s,     Z: {}", s.icmps(), baselineService.calculateZScore("ICMPS_PER_SEC", s.icmps));
        log.info("Śr. rozm. pkt:   {} bytes,     Z: {}", String.format("%.2f", s.avgPacketSize()), baselineService.calculateZScore("AVG_PACKET_SIZE", s.avgPacketSize));
        log.info("Asymetria (I/O): {},           Z: {}", String.format("%.2f", s.asymmetry()), baselineService.calculateZScore("TRAFFIC_ASYMMETRY", s.asymmetry));
        log.info("Aktywne Flowy:   {},           Z: {}", s.flows(), baselineService.calculateZScore("ACTIVE_FLOWS", s.flows));
        log.info("Ilość unikalnych portów:   {}, Z: {}", s.portDiversity, baselineService.calculateZScore("GLOBAL_PORT_DIVERSITY", s.portDiversity));
        log.info("------------------------------------");

        double anomalyProbability = fuzzyService.analyze(s.syns, s.icmps, s.avgPacketSize, s.asymmetry, s.flows, s.portDiversity);

        log.info("--- ANALIZA ZAGROŻEŃ ---");
        log.info("Prawdopodobieństwo anomalii: {}%", String.format("%.2f", anomalyProbability));

        if (anomalyProbability > 70) {
            log.error("!!! WYKRYTO POWAŻNĄ ANOMALIĘ !!!");
        }

        baselineService.addObservation("SYNS_PER_SEC", s.syns, anomalyProbability);
        baselineService.addObservation("ICMPS_PER_SEC", s.icmps, anomalyProbability);
        baselineService.addObservation("AVG_PACKET_SIZE", s.avgPacketSize, anomalyProbability);
        baselineService.addObservation("TRAFFIC_ASYMMETRY", s.asymmetry, anomalyProbability);
        baselineService.addObservation("ACTIVE_FLOWS", s.flows, anomalyProbability);
        baselineService.addObservation("GLOBAL_PORT_DIVERSITY", s.portDiversity, anomalyProbability);
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