package com.ids.ids_controller.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

@Service
public class BaselineService {
    private static final Logger log = LoggerFactory.getLogger(BaselineService.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    // ConcurrentLinkedDeque jest bezpieczna dla wielu wątków (lock-free)
    private final Map<String, Deque<Double>> historyMap = new ConcurrentHashMap<>();
    private final int MAX_WINDOW_SIZE = 86400; // 24h

    private final Map<String, BaselineStats> currentStats = new ConcurrentHashMap<>();;

    public void addObservation(String featureName, double value) {
        BaselineStats stats = currentStats.computeIfAbsent(featureName, k -> new BaselineStats());

        // OBLICZAMY Z-SCORE ZANIM DODAMY DANE
        double z = calculateZScore(featureName, value);

        if (Math.abs(z) > 5.0 && stats.getCount() > 100) {
            log.warn("Pominięto aktualizację baseline dla {} - wykryto silną anomalię (Z={})", featureName, z);
            return;
        }

        // Standardowe przesuwanie okna (Deque)
        Deque<Double> history = historyMap.computeIfAbsent(featureName, k -> new ConcurrentLinkedDeque<>());
        if (history.size() >= MAX_WINDOW_SIZE) {
            Double oldest = history.pollFirst();
            if (oldest != null) stats.remove(oldest);
        }
        history.addLast(value);
        stats.update(value); // Używamy nowej metody Welforda
    }

    public double calculateZScore(String featureName, double currentValue) {
        BaselineStats stats = currentStats.get(featureName);

        // Z-Score wymaga minimum danych, by mieć sens statystyczny (np. 30 próbek)
        if (stats == null || stats.getCount() < 30) return 0.0;

        double mean = stats.getMean();
        double stdDev = stats.getStdDev();

        // Jeśli odchylenie jest bliskie zeru, każdy ruch inny niż średnia byłby nieskończoną anomalią
        if (stdDev < 0.0001) return 0.0;

        return (currentValue - mean) / stdDev;
    }

    public Map<String, BaselineStats> getCurrentProfile() {
        return Collections.unmodifiableMap(currentStats);
    }

    public void exportProfile(String filePath) throws IOException {
        Map<String, BaselineStatsDTO> exportData = new HashMap<>();
        currentStats.forEach((key, stats) -> {
            exportData.put(key, new BaselineStatsDTO(stats.getCount(), stats.getMean(), stats.getM2()));
        });
        objectMapper.writeValue(new File(filePath), exportData);
        log.info("Wyeksportowano profil baseline do: {}", filePath);
    }

    /**
     * Wczytuje profil statystyczny z pliku JSON.
     * Pozwala to na natychmiastowe ustawienie baselinu bez fazy uczenia.
     */
    public void importProfile(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) return;

        Map<String, BaselineStatsDTO> importedData = objectMapper.readValue(file,
                objectMapper.getTypeFactory().constructMapType(HashMap.class, String.class, BaselineStatsDTO.class));

        importedData.forEach((key, dto) -> {
            BaselineStats stats = new BaselineStats();
            stats.setFromDTO(dto.count, dto.mean, dto.m2);
            currentStats.put(key, stats);
        });
        log.info("Zaimportowano profil baseline z pliku: {}. Cechy: {}", filePath, currentStats.keySet());
    }

    // ALGORYTM WELFORDA
    public static class BaselineStats {
        private long count = 0;
        private double mean = 0.0;
        private double m2 = 0.0;

        public synchronized void update(double x) {
            count++;
            double delta = x - mean;
            mean += delta / count;
            double delta2 = x - mean;
            m2 += delta * delta2;
        }

        public synchronized void remove(double x) {
            if (count <= 1) {
                count = 0; mean = 0; m2 = 0;
                return;
            }
            double oldMean = (count * mean - x) / (count - 1);
            m2 -= (x - mean) * (x - oldMean);
            mean = oldMean;
            count--;
        }

        public synchronized void setFromDTO(long count, double mean, double m2) {
            this.count = count;
            this.mean = mean;
            this.m2 = m2;
        }

        public synchronized long getCount() { return count; }
        public synchronized double getMean() { return mean; }
        public synchronized double getM2() { return m2; }
        public synchronized double getStdDev() {
            return (count < 2) ? 0.0 : Math.sqrt(m2 / (count - 1));
        }
    }

    private record BaselineStatsDTO(
            @JsonProperty("count") long count,
            @JsonProperty("mean") double mean,
            @JsonProperty("m2") double m2
    ) {}
}