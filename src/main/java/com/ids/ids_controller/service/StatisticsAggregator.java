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
    private Disposable subscription; // Referencja do subskrypcji, by móc ją zamknąć

    public StatisticsAggregator(FeatureExtractor featureExtractor, BaselineService baselineService) {
        this.featureExtractor = featureExtractor;
        this.baselineService = baselineService;
    }

    @PostConstruct
    public void init() {
        log.info("Inicjalizacja reaktywnego agregatora statystyk...");

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
        // pobieranie danych z FeatureExtractor + reset
        NetworkSnapshot snapshot = new NetworkSnapshot(
                featureExtractor.getAndResetSynCount(),
                featureExtractor.getAndResetIcmpCount(),
                featureExtractor.getAvgPacketSize(),
                featureExtractor.getTrafficAsymmetry(),
                featureExtractor.getActiveFlowsCount(),
                featureExtractor.getAndResetPortVariety()
        );

        featureExtractor.resetAll();

        return snapshot;
    }

    private void logSnapshot(NetworkSnapshot s) {
        log.info("--- NETWORK SNAPSHOT (REACTIVE) ---");
        log.info("Liczników SYN:   {} pkt/s", s.syns());
        log.info("Liczników ICMP:  {} pkt/s", s.icmps());
        log.info("Śr. rozm. pkt:   {} bytes", String.format("%.2f", s.avgPacketSize()));
        log.info("Asymetria (I/O): {}", String.format("%.2f", s.asymmetry()));
        log.info("Aktywne Flowy:   {}", s.flows());

        long seriousScanners = s.portVariety().entrySet().stream()
                .filter(e -> e.getValue() > 1)
                .peek(e -> log.warn("Possible Scanner: IP {} touched {} unique ports", e.getKey(), e.getValue()))
                .count();

        if (s.portVariety().size() > 100) {
            log.warn("DETECTED: High volume of unique source IPs ({}) - possible Distributed Attack!", s.portVariety().size());
        }
        log.info("------------------------------------");
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
            Map<String, Integer> portVariety
    ) {}
}