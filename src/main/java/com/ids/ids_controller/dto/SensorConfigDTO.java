package com.ids.ids_controller.dto;

public record SensorConfigDTO(
        String sensorId,
        String name,
        String hostname,
        String model,
        String location
) {}