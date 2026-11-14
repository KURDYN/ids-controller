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

    public double analyze(double zSyn, double zIcmp, double zAvgSize,
                          double zAsym, double zFlows, double zPorts) {

        double msi = Double.max(zSyn, zIcmp);
        if (msi < 0) msi = 0;
        fis.setVariable("MSI", msi);
        if (zPorts < 0) zPorts = 0;
        fis.setVariable("PVAR", zPorts);
        zAvgSize = Math.abs(zAvgSize);
        fis.setVariable("SIZE", zAvgSize);
        zAsym = Math.abs(zAsym);
        fis.setVariable("ASSM", zAsym);
        if (zFlows < 0) zFlows = 0;
        fis.setVariable("FLOWS", zFlows);

        fis.evaluate();

        return fis.getVariable("FIDS_SCORE").getValue();
    }
}