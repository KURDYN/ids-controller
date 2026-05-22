package com.ids.ids_controller.model;

import java.time.Instant;

public record Incident(
        String id,
        String sensorId,
        Instant timestamp,
        String description,
        double maxProbability,
        byte[] pcapData
) {
    public String getId() { return id; }
    public String getSensorId() { return sensorId; }
}
