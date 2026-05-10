package com.ids.ids_controller.api;

import com.ids.ids_controller.service.BaselineService;
import com.ids.ids_controller.service.StatisticsAggregator;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import reactor.core.publisher.Flux;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.Map;

@Controller
@RequestMapping("/dashboard")
public class DashboardController {

    private final BaselineService baselineService;
    private final StatisticsAggregator aggregator;

    public DashboardController(BaselineService baselineService, StatisticsAggregator aggregator) {
        this.baselineService = baselineService;
        this.aggregator = aggregator;
    }

    @GetMapping
    public String index(Model model) {
        // Thymeleaf wyrenderuje szkielet strony
        return "index";
    }

    // Reaktywne API przesyłające dane w formacie Server-Sent Events (SSE)
    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    @ResponseBody
    public Flux<Map<String, Double>> streamMetrics() {
        return Flux.interval(Duration.ofSeconds(1))
                .map(sequence -> aggregator.getCurrentMetrics()) // Musisz dodać tę metodę w aggregatorze
                .subscribeOn(Schedulers.boundedElastic());
    }
}
