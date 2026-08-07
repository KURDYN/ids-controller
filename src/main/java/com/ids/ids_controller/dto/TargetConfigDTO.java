package com.ids.ids_controller.dto;

public record TargetConfigDTO(
        String targetIp,
        String name,
        String hostname,
        String location
) {}
