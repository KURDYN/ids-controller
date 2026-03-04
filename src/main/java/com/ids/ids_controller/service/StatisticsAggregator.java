package com.ids.ids_controller.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@EnableScheduling // włączenie schedulingu
public class StatisticsAggregator {
    private static final Logger log = LoggerFactory.getLogger(StatisticsAggregator.class);

    private final FeatureExtractor featureExtractor;
    private final BaselineService baselineService;

    public StatisticsAggregator(FeatureExtractor featureExtractor, BaselineService baselineService) {
        this.featureExtractor = featureExtractor;
        this.baselineService = baselineService;
    }

    @Scheduled(fixedRate = 1000)
    public void aggregateAndAnalyze() {
        // 1. Pobranie surowych danych i reset liczników w FeatureExtractor
        int syns = featureExtractor.getAndResetSynCount();
        int icmps = featureExtractor.getAndResetIcmpCount();
        double avgPacketSize = featureExtractor.getAvgPacketSize();
        double asymmetry = featureExtractor.getTrafficAsymmetry();
        int flows = featureExtractor.getActiveFlowsCount();
        Map<String, Integer> portVariety = featureExtractor.getAndResetPortVariety();

        // Resetujemy FeatureExtractor na koniec zbierania danych
        featureExtractor.resetAll();

        log.info("--- NETWORK SNAPSHOT ---");
        log.info("Liczników SYN:   {} pkt/s", syns);
        log.info("Liczników ICMP:  {} pkt/s", icmps);
        log.info("Śr. rozm. pkt:   {} bytes", String.format("%.2f", avgPacketSize));
        log.info("Asymetria (I/O): {}", String.format("%.2f", asymmetry));
        log.info("Aktywne Flowy:   {}", flows);
        long seriousScanners = portVariety.entrySet().stream()
                .filter(e -> e.getValue() > 1)
                .peek(e -> log.warn("Possible Scanner: IP {} touched {} unique ports", e.getKey(), e.getValue()))
                .count();
        int randomIpCount = portVariety.size();
        if (randomIpCount > 100) {
            log.warn("DETECTED: High volume of unique source IPs ({}) - possible Distributed Attack!", randomIpCount);
        }
        log.info("------------------------");

        int minuteOfDay = java.time.LocalTime.now().get(java.time.temporal.ChronoField.MINUTE_OF_DAY);

        // TODO 3. Obliczanie odchyleń dla każdej cechy
    }
}