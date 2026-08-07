package com.ids.ids_controller.model;

import java.time.Instant;
import java.util.List;

public record Incident(
        String id,
        String sensorId,
        String targetIp,
        List<String> sourceIps,
        Instant timestamp,
        String description,
        double maxProbability,
        byte[] pcapData,
        String idmefJson
) {
    public String getId() { return id; }
    public String getSensorId() { return sensorId; }
    public String getTargetIp() {
        return targetIp;
    }

    public List<String> getSourceIps() {
        return sourceIps;
    }
}
