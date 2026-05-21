package com.ids.ids_controller.model;

import java.time.Instant;

public record Incident(
        String id,
        Instant timestamp,
        String description,
        double maxProbability,
        byte[] pcapData
) {}
