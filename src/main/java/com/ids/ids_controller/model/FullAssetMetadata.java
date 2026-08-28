package com.ids.ids_controller.model;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class FullAssetMetadata {
    private Map<String, SensorMetadata> sensors = new ConcurrentHashMap<>();
    private Map<String, TargetMetadata> targets = new ConcurrentHashMap<>();

    public Map<String, SensorMetadata> getSensors() { return sensors; }
    public void setSensors(Map<String, SensorMetadata> sensors) { this.sensors = sensors; }

    public Map<String, TargetMetadata> getTargets() { return targets; }
    public void setTargets(Map<String, TargetMetadata> targets) { this.targets = targets; }

}
