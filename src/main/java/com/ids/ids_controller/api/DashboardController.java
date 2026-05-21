package com.ids.ids_controller.api;

import com.ids.ids_controller.model.Incident;
import com.ids.ids_controller.service.BaselineService;
import com.ids.ids_controller.service.IncidentService;
import com.ids.ids_controller.service.StatisticsAggregator;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.Map;

@Controller
@RequestMapping("/dashboard")
public class DashboardController {

    private final BaselineService baselineService;
    private final StatisticsAggregator aggregator;
    private final IncidentService incidentService;

    public DashboardController(BaselineService baselineService, StatisticsAggregator aggregator, IncidentService incidentService) {
        this.baselineService = baselineService;
        this.aggregator = aggregator;
        this.incidentService = incidentService;
    }

    @GetMapping
    public String index(Model model) {
        return "index";
    }

    // reaktywne API przesyłające dane w formacie Server-Sent Events (SSE)
    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @ResponseBody
    public Flux<Map<String, Double>> streamMetrics() {
        return Flux.interval(Duration.ofSeconds(1))
                .map(sequence -> aggregator.getCurrentMetrics())
                .subscribeOn(Schedulers.boundedElastic());
    }

    @GetMapping(value = "/incidents/{id}/pcap", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    @ResponseBody
    public Mono<ResponseEntity<byte[]>> downloadPcap(@PathVariable String id) {
        return Mono.justOrEmpty(incidentService.getIncident(id))
                .map(incident -> ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"incident_" + id.substring(0,8) + ".pcap\"")
                        .body(incident.pcapData()))
                .defaultIfEmpty(ResponseEntity.notFound().build())
                .subscribeOn(Schedulers.boundedElastic());
    }

    // Endpoint zwracający aktualną listę incydentów w formacie JSON
    @GetMapping("/incidents")
    @ResponseBody
    public Flux<Incident> getIncidentsList() {
        return Flux.fromIterable(incidentService.getAllIncidents())
                .subscribeOn(Schedulers.boundedElastic());
    }
}
