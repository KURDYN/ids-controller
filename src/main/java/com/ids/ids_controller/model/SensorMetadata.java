package com.ids.ids_controller.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SensorMetadata {
    @JsonProperty("name")
    private String name;
    @JsonProperty("hostname")
    private String hostname;
    @JsonProperty("model")
    private String model;
    @JsonProperty("location")
    private String location;

    // Bezargumentowy konstruktor wymagany przez Jacksona do deserializacji
    public SensorMetadata() {}

    public SensorMetadata(String name, String hostname, String model, String location) {
        this.name = name;
        this.hostname = hostname;
        this.model = model;
        this.location = location;
    }

    // Gettery i Settery
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }
    public String getModel() { return model; }
    public void setModel(String model) { this.model = model; }
    public String getLocation() { return location; }
    public void setLocation(String location) { this.location = location; }
}
