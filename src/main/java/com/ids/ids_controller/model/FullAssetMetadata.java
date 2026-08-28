package com.ids.ids_controller.model;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

public class FullAssetMetadata {
    private Map<String, SensorMetadata> sensors = new ConcurrentHashMap<>();
    private Map<String, TargetMetadata> targets = new ConcurrentHashMap<>();
    private List<SiemTargetMetadata> siemTargets = new CopyOnWriteArrayList<>();

    public Map<String, SensorMetadata> getSensors() { return sensors; }
    public void setSensors(Map<String, SensorMetadata> sensors) { this.sensors = sensors; }

    public Map<String, TargetMetadata> getTargets() { return targets; }
    public void setTargets(Map<String, TargetMetadata> targets) { this.targets = targets; }

    public List<SiemTargetMetadata> getSiemTargets() { return siemTargets; }
    public void setSiemTargets(List<SiemTargetMetadata> siemTargets) { this.siemTargets = siemTargets; }


}
