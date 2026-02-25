package com.ids.ids_controller.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@EnableScheduling // Włącza obsługę harmonogramu zadań
public class StatisticsAggregator {
    private static final Logger log = LoggerFactory.getLogger(StatisticsAggregator.class);

    private final FeatureExtractor featureExtractor;

    public StatisticsAggregator(FeatureExtractor featureExtractor) {
        this.featureExtractor = featureExtractor;
    }

    // Wykonuj co 1000ms (1 sekunda)
    @Scheduled(fixedRate = 1000)
    public void aggregateAndLog() {
        int synsLastSecond = featureExtractor.getAndResetSynCount();
        int icmpsLastSecond = featureExtractor.getAndResetIcmpCount();
        int sshLastSecond = featureExtractor.getAndResetSshAttempts();
        Map<String, Integer> portVariety = featureExtractor.getAndResetPortVariety();

        log.info("--- RAPORT SEKUNDOWY ---");
        log.info("TCP SYN Rate: {} pkt/s", synsLastSecond);
        log.info("ICMP Rate:    {} pkt/s", icmpsLastSecond);
        log.info("SSH PSH Rate: {} pkt/s", sshLastSecond);

        if (!portVariety.isEmpty()) {
            portVariety.forEach((ip, count) ->
                    log.info("Scanner Alert: IP {} dotknęło {} unikalnych portów", ip, count)
            );
        }
        log.info("------------------------");

    }
}