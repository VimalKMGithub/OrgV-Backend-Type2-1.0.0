package org.v.gateway.service.filters;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class GateWayCorsWebFilter extends CorsWebFilter {
    public GateWayCorsWebFilter(UrlBasedCorsConfigurationSource source) {
        super(source);
    }
}
