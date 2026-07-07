package com.ids.ids_controller.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TargetMetadata {
    @JsonProperty("name")
    private String name;
    @JsonProperty("hostname")
    private String hostname;
    @JsonProperty("location")
    private String location;

    public TargetMetadata() {}

    public TargetMetadata(String name, String hostname, String location) {
        this.name = name;
        this.hostname = hostname;
        this.location = location;
    }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }
    public String getLocation() { return location; }
    public void setLocation(String location) { this.location = location; }
}
