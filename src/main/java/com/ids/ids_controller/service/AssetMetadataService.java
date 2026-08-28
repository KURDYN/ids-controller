package com.ids.ids_controller.service;

import com.ids.ids_controller.model.FullAssetMetadata;
import com.ids.ids_controller.model.SensorMetadata;
import com.ids.ids_controller.model.SiemTargetMetadata;
import com.ids.ids_controller.model.TargetMetadata;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.io.File;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class AssetMetadataService {
    private static final Logger log = LoggerFactory.getLogger(AssetMetadataService.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String CONFIG_FILE_PATH = "asset_config.json";

    private FullAssetMetadata config = new FullAssetMetadata();

    @PostConstruct
    public void init() {
        try {
            File file = new File(CONFIG_FILE_PATH);
            if (file.exists()) {
                this.config = objectMapper.readValue(file, FullAssetMetadata.class);
                log.info("Zaimportowano konfigurację assetów z pliku JSON.");
            } else {
                log.info("Brak pliku konfiguracji assetów. Utworzono nowy czysty profil.");
            }
        } catch (Exception e) {
            log.error("Błąd podczas ładowania konfiguracji assetów: ", e);
        }
    }

    public synchronized void updateSensorMetadata(String sensorId, SensorMetadata meta) {
        config.getSensors().put(sensorId, meta);
        asyncExport();
    }

    public synchronized void updateTargetMetadata(String targetIp, TargetMetadata meta) {
        config.getTargets().put(targetIp, meta);
        asyncExport();
    }

    public SensorMetadata getSensorMetadata(String sensorId) {
        return config.getSensors().get(sensorId);
    }

    public TargetMetadata getTargetMetadata(String targetIp) {
        return config.getTargets().get(targetIp);
    }

    public List<SiemTargetMetadata> getSiemTargets() {
        if (config.getSiemTargets() == null) {
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(config.getSiemTargets());
    }

    public synchronized void addOrUpdateSiemTarget(SiemTargetMetadata target) {
        if (config.getSiemTargets() == null) {
            return;
        }

        if (target.getId() == null || target.getId().isBlank()) {
            target.setId(UUID.randomUUID().toString());
        }

        config.getSiemTargets().removeIf(t -> t.getId().equals(target.getId()));
        config.getSiemTargets().add(target);
        asyncExport();
    }

    public synchronized void deleteSiemTarget(String id) {
        if (config.getSiemTargets() != null) {
            config.getSiemTargets().removeIf(t -> t.getId().equals(id));
            asyncExport();
        }
    }

    // Wykorzystywane przez UI do pobrania unikalnych celów
    public Set<String> getActiveTargets() {
        return config.getTargets().keySet();
    }

    public FullAssetMetadata getFullConfiguration() {
        return this.config;
    }

    public synchronized void importFullConfiguration(FullAssetMetadata newConfig) {
        if (newConfig != null) {
            if (newConfig.getSensors() != null) {
                this.config.getSensors().putAll(newConfig.getSensors());
            }
            if (newConfig.getTargets() != null) {
                this.config.getTargets().putAll(newConfig.getTargets());
            }
            if (newConfig.getSiemTargets() != null) {
                this.config.getSiemTargets().clear();
                this.config.getSiemTargets().addAll(newConfig.getSiemTargets());
            }
            asyncExport();
        }
    }

    // Automatyczna rejestracja pustego profilu Targetu, jeśli jeszcze nie istnieje w JSON
    public synchronized void registerTargetIfAbsent(String targetIp) {
        if (!config.getTargets().containsKey(targetIp)) {
            config.getTargets().put(targetIp, new TargetMetadata("null", "null", "null"));
            asyncExport();
        }
    }

    private void asyncExport() {
        CompletableFuture.runAsync(() -> {
            try {
                objectMapper.writeValue(new File(CONFIG_FILE_PATH), config);
                log.info("Konfiguracja assetów została pomyślnie zautozapisana na dysku.");
            } catch (Exception e) {
                log.error("Błąd podczas asynchronicznego auto-zapisu: ", e);
            }
        });
    }

}