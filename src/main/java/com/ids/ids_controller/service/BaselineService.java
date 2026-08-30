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

    private final int MAX_WINDOW_SIZE = 86400; // 24h

    private final Map<String, BaselineStats> currentStats = new ConcurrentHashMap<>();;

    public void addObservation(String featureName, double rawValue, double zScoreValue, double anomalyProbability) {
        BaselineStats stats = currentStats.computeIfAbsent(featureName, k -> new BaselineStats());

        if (anomalyProbability > 60.0 && stats.getCount() > 30) {
            log.warn("Pominięto aktualizację baseline dla {} - wykryto silną anomalię", featureName);
            return;
        }

        // 1. Profil uczący aktualizuje się surową wartością
        stats.update(rawValue);

        // 2. Do historii dla wykresu trafia wyliczony Z-Score
        Deque<Double> history = historyMap.computeIfAbsent(featureName, k -> new ConcurrentLinkedDeque<>());
        if (history.size() >= MAX_WINDOW_SIZE) {
            history.pollFirst();
        }
        history.addLast(zScoreValue);
    }

    public void recordSensorState(String sensorId, double anomalyProbability) {
        long now = Instant.now().toEpochMilli();

        Deque<Long> timestamps = timestampsMap.computeIfAbsent(sensorId, k -> new ConcurrentLinkedDeque<>());
        Deque<Double> anomalies = anomalyHistoryMap.computeIfAbsent(sensorId, k -> new ConcurrentLinkedDeque<>());

        if (timestamps.size() >= MAX_WINDOW_SIZE) {
            timestamps.pollFirst();
            anomalies.pollFirst();
        }

        timestamps.addLast(now);
        anomalies.addLast(anomalyProbability);
    }

    // Pobieranie skompletowanej historii z bufora dla wskazanego sensora
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
        Deque<Double> asym = historyMap.get(prefix + "TRAFFIC_ASYMMETRY");
        Deque<Double> flows = historyMap.get(prefix + "ACTIVE_FLOWS");
        Deque<Double> portVar = historyMap.get(prefix + "GLOBAL_PORT_DIVERSITY");

        List<Map<String, Object>> result = new ArrayList<>();

        Iterator<Long> timeIt = timestamps.iterator();
        Iterator<Double> anomIt = anomalies != null ? anomalies.iterator() : null;
        Iterator<Double> synsIt = syns != null ? syns.iterator() : null;
        Iterator<Double> icmpsIt = icmps != null ? icmps.iterator() : null;
        Iterator<Double> avgSizeIt = avgSize != null ? avgSize.iterator() : null;
        Iterator<Double> asymIt = asym != null ? asym.iterator() : null;
        Iterator<Double> flowsIt = flows != null ? flows.iterator() : null;
        Iterator<Double> portVarIt = portVar != null ? portVar.iterator() : null;

        while (timeIt.hasNext()) {
            Map<String, Object> point = new HashMap<>();
            point.put("timestamp", timeIt.next());
            point.put("anomalyProbability", (anomIt != null && anomIt.hasNext()) ? anomIt.next() : 0.0);
            point.put("zSyn", (synsIt != null && synsIt.hasNext()) ? synsIt.next() : 0.0);
            point.put("zIcmp", (icmpsIt != null && icmpsIt.hasNext()) ? icmpsIt.next() : 0.0);
            point.put("zAvgSize", (avgSizeIt != null && avgSizeIt.hasNext()) ? avgSizeIt.next() : 0.0);
            point.put("zAsym", (asymIt != null && asymIt.hasNext()) ? asymIt.next() : 0.0);
            point.put("zFlows", (flowsIt != null && flowsIt.hasNext()) ? flowsIt.next() : 0.0);
            point.put("zPortVar", (portVarIt != null && portVarIt.hasNext()) ? portVarIt.next() : 0.0);

            result.add(point);
        }

        return result;
    }

    public double calculateZScore(String featureName, double currentValue) {
        BaselineStats stats = currentStats.get(featureName);

        if (stats == null || stats.getCount() < 30) return 0.0;

        double mean = stats.getMean();
        double stdDev = stats.getStdDev();

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