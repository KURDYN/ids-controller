package com.ids.ids_controller.api;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardViewController {


    @GetMapping({"/", "/dashboard"})
    public String dashboard() {
        return "dashboard"; // zwraca dashboard.html (lub alerts.html)
    }


    @GetMapping("/sensors")
    public String sensors() {
        return "sensors"; // zwraca sensors.html
    }


    @GetMapping("/metadata")
    public String metadata() {
        return "metadata"; // zwraca metadata.html
    }
}