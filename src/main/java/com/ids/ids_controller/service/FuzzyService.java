package com.ids.ids_controller.service;

import net.sourceforge.jFuzzyLogic.FIS;
import org.springframework.stereotype.Service;

@Service
public class FuzzyService {

    private final FIS fis;

    public FuzzyService() {
        // Wczytanie pliku FCL z zasobów
        String fileName = "network_anomaly.fcl";
        this.fis = FIS.load(getClass().getClassLoader().getResourceAsStream(fileName), true);

        if (fis == null) {
            throw new RuntimeException("Nie można wczytać pliku FCL: " + fileName);
        }
    }

    public double analyze(double zSyn, double zIcmp, double zAvgSize,
                          double zAsym, double zFlows, double zPorts) {
        fis.setVariable("z_syns", zSyn);
        fis.setVariable("z_icmps", zIcmp);
        fis.setVariable("z_avg_size", zAvgSize);
        fis.setVariable("z_asymmetry", zAsym);
        fis.setVariable("z_flows", zFlows);
        fis.setVariable("z_ports", zPorts);

        fis.evaluate();

        return fis.getVariable("anomaly_probability").getValue();
    }
}