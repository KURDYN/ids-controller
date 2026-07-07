package com.ids.ids_controller.service;

import com.ids.ids_controller.model.FullAssetMetadata;
import com.ids.ids_controller.model.SensorMetadata;
import com.ids.ids_controller.model.TargetMetadata;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.io.File;
import java.util.concurrent.CompletableFuture;

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