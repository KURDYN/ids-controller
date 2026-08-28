package com.ids.ids_controller.model;

import java.util.Objects;

public class SiemTargetMetadata {
    private String id;        // np. UUID lub automatycznie wygenerowany identyfikator
    private String name;      // Nazwa przyjazna dla użytkownika, np. "Primary SIEM"
    private String host;      // IP lub hostname, np. "172.16.0.99"
    private int port;         // Port, np. 4690
    private boolean enabled;  // Przełącznik aktywności (true/false)

    public SiemTargetMetadata() {
    }

    public SiemTargetMetadata(String id, String name, String host, int port, boolean enabled) {
        this.id = id;
        this.name = name;
        this.host = host;
        this.port = port;
        this.enabled = enabled;
    }

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }

    public int getPort() { return port; }
    public void setPort(int port) { this.port = port; }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SiemTargetMetadata that = (SiemTargetMetadata) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}