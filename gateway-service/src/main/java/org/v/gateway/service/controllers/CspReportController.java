package org.v.gateway.service.controllers;

import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@Slf4j
@RestController
public class CspReportController {
    @PostMapping("/csp-report")
    public Mono<Void> cspReport(@RequestBody String body) {
        log.warn("Csp Violation Detected: {}", body);
        return Mono.empty();
    }
}
