package com.ids.ids_controller.service;

import net.sourceforge.jFuzzyLogic.FIS;
import org.springframework.stereotype.Service;

@Service
public class FuzzyService {

    private final FIS fis;

    public FuzzyService() {
        String fileName = "fuzzyIDS.fcl";
        this.fis = FIS.load(getClass().getClassLoader().getResourceAsStream(fileName), true);

        if (fis == null) {
            throw new RuntimeException("Nie można wczytać pliku FCL: " + fileName);
        }
    }

    public double analyze(double zSyn, double zIcmp, double zAvgSize, double zTrafficVolume, double zFlows, double zPorts) {
        double msi = Math.max(zSyn, zIcmp);
        msi = Math.max(0.0, msi);
        double pvar = Math.max(0.0, zPorts);
        double size = Math.abs(zAvgSize);
        double volume = Math.max(0.0, zTrafficVolume);
        double flows = Math.max(0.0, zFlows);

        fis.setVariable("MSI", msi);
        fis.setVariable("PVAR", pvar);
        fis.setVariable("SIZE", size);
        fis.setVariable("VOL", volume);
        fis.setVariable("FLOWS", flows);

        fis.evaluate();

        return fis.getVariable("FIDS_SCORE").getValue();
    }
}