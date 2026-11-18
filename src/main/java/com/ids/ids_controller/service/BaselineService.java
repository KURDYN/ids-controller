
package com.ids.ids_controller.service;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

@Service
public class BaselineService {
    private static final Logger log = LoggerFactory.getLogger(BaselineService.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final Map<String, Deque<Double>> historyMap = new ConcurrentHashMap<>();
    private final Map<String, Deque<Long>> timestampsMap = new ConcurrentHashMap<>();
    private final Map<String, Deque<Double>> anomalyHistoryMap = new ConcurrentHashMap<>();

    private static final int MAX_WINDOW_SIZE = 86400;
    private final Map<String, BaselineStats> currentStats = new ConcurrentHashMap<>();

    public void addObservation(String featureName, double rawValue, double zScoreValue, boolean attackDetected) {
        if (!Double.isFinite(rawValue) || !Double.isFinite(zScoreValue)) {
            log.warn("Pominięto nieprawidłową obserwację dla {}: raw={}, z={}", featureName, rawValue, zScoreValue);
            return;
        }

        BaselineStats stats = currentStats.computeIfAbsent(featureName, k -> new BaselineStats());

        if (attackDetected) {
            log.debug("Pominięto aktualizację baseline dla {} - trwa atak.", featureName);
        } else stats.update(rawValue);

        appendBounded(historyMap.computeIfAbsent(featureName, k -> new ConcurrentLinkedDeque<>()), zScoreValue);
    }

    private void appendBounded(Deque<Double> history, double value) {
        while (history.size() >= MAX_WINDOW_SIZE) {
            history.pollFirst();
        }
        history.addLast(value);
    }

    private void appendBounded(Deque<Long> history, long value) {
        while (history.size() >= MAX_WINDOW_SIZE) {
            history.pollFirst();
        }
        history.addLast(value);
    }

    private Double nextOrZero(Iterator<Double> iterator) {
        return iterator != null && iterator.hasNext() ? iterator.next() : 0.0;
    }

    // HISTORIA STANU SENSORA
    public void recordSensorState(String sensorId, double anomalyProbability) {
        if (!Double.isFinite(anomalyProbability)) {
            log.warn("Pominięto nieprawidłowe prawdopodobieństwo anomalii dla {}", sensorId);
            return;
        }

        long now = Instant.now().toEpochMilli();

        Deque<Long> timestamps = timestampsMap.computeIfAbsent(sensorId, k -> new ConcurrentLinkedDeque<>());
        Deque<Double> anomalies = anomalyHistoryMap.computeIfAbsent(sensorId, k -> new ConcurrentLinkedDeque<>());

        appendBounded(timestamps, now);
        appendBounded(anomalies, anomalyProbability);
    }

    // POBIERANIE HISTORII DLA WYKRESÓW
    public List<Map<String, Object>> getSensorHistory(String sensorId) {
        Deque<Long> timestamps = timestampsMap.get(sensorId);

        if (timestamps == null || timestamps.isEmpty()) {
            return Collections.emptyList();
        }

        String prefix = sensorId + ":";
        Deque<Double> anomalies = anomalyHistoryMap.get(sensorId);
        Deque<Double> syns = historyMap.get(prefix + "SYNS_PER_SEC");
        Deque<Double> icmps = historyMap.get(prefix + "ICMPS_PER_SEC");
        Deque<Double> avgSize = historyMap.get(prefix + "AVG_PACKET_SIZE");
        Deque<Double> trafficVolume = historyMap.get(prefix + "TRAFFIC_VOLUME_BYTES_PER_SEC");
        Deque<Double> flows = historyMap.get(prefix + "ACTIVE_FLOWS");
        Deque<Double> portVar = historyMap.get(prefix + "GLOBAL_PORT_DIVERSITY");
        List<Map<String, Object>> result = new ArrayList<>();
        Iterator<Long> timeIt = timestamps.iterator();

        Iterator<Double> anomIt = anomalies != null ? anomalies.iterator() : null;
        Iterator<Double> synsIt = syns != null ? syns.iterator() : null;
        Iterator<Double> icmpsIt = icmps != null ? icmps.iterator() : null;
        Iterator<Double> avgSizeIt = avgSize != null ? avgSize.iterator() : null;
        Iterator<Double> trafficVolumeIt = trafficVolume != null ? trafficVolume.iterator() : null;
        Iterator<Double> flowsIt = flows != null ? flows.iterator() : null;
        Iterator<Double> portVarIt = portVar != null ? portVar.iterator() : null;

        while (timeIt.hasNext()) {
            Map<String, Object> point = new HashMap<>();
            point.put("timestamp", timeIt.next());
            point.put("anomalyProbability", nextOrZero(anomIt));
            point.put("zSyn", nextOrZero(synsIt));
            point.put("zIcmp", nextOrZero(icmpsIt));
            point.put("zAvgSize", nextOrZero(avgSizeIt));
            point.put("zTrafficVolume", nextOrZero(trafficVolumeIt));
            point.put("zFlows", nextOrZero(flowsIt));
            point.put("zPortVar", nextOrZero(portVarIt));

            result.add(point);
        }

        return result;
    }

    public double calculateZScore(String featureName, double currentValue) {

        if (!Double.isFinite(currentValue)) {
            return 0.0;
        }

        BaselineStats stats = currentStats.get(featureName);

        // Minimum 30 obserwacji do rozpoczęcia analizy.
        if (stats == null || stats.getCount() < 30) {
            return 0.0;
        }

        double mean = stats.getMean();
        double stdDev = stats.getStdDev();

        if (!Double.isFinite(stdDev) || stdDev < 0.0001) {
            return 0.0;
        }

        return (currentValue - mean) / stdDev;
    }

    public Map<String, BaselineStats> getCurrentProfile() {
        return Collections.unmodifiableMap(currentStats);
    }

    // EKSPORT PROFILU
    public void exportProfile(String filePath) throws IOException {
        Map<String, BaselineStatsDTO> exportData = new HashMap<>();

        currentStats.forEach((key, stats) -> {
            exportData.put(key, new BaselineStatsDTO(stats.getCount(), stats.getMean(), stats.getM2()));
        });

        objectMapper.writeValue(new File(filePath), exportData);

        log.info("Wyeksportowano profil baseline do: {}", filePath);
    }

    // IMPORT PROFILU
    public void importProfile(String filePath) throws IOException {
        File file = new File(filePath);

        if (!file.exists()) {
            log.warn("Nie znaleziono pliku profilu baseline: {}", filePath);
            return;
        }

        Map<String, BaselineStatsDTO> importedData = objectMapper.readValue(file, objectMapper.getTypeFactory().constructMapType(HashMap.class, String.class, BaselineStatsDTO.class));

        importedData.forEach((key, dto) -> {
            if (dto.count() < 0 || !Double.isFinite(dto.mean()) || !Double.isFinite(dto.m2()) || dto.m2() < 0) {
                log.warn("Pominięto nieprawidłowy profil baseline: {}", key);
                return;
            }

            BaselineStats stats = new BaselineStats();
            stats.setFromDTO(dto.count(), dto.mean(), dto.m2());
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
            if (!Double.isFinite(x)) {
                throw new IllegalArgumentException(
                        "Wartość obserwacji musi być skończona."
                );
            }
            count++;

            double delta = x - mean;
            mean += delta / count;

            double delta2 = x - mean;
            m2 += delta * delta2;
        }

        public synchronized void remove(double x) {
            if (count <= 1) {
                count = 0;
                mean = 0;
                m2 = 0;
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

        public synchronized long getCount() {
            return count;
        }

        public synchronized double getMean() {
            return mean;
        }

        public synchronized double getM2() {
            return m2;
        }

        public synchronized double getStdDev() {
            return (count < 2) ? 0.0 : Math.sqrt(m2 / (count - 1));
        }
    }
    private record BaselineStatsDTO(
            @JsonProperty("count") long count,
            @JsonProperty("mean") double mean,
            @JsonProperty("m2") double m2
    ) {
    }
}
