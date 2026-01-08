package org.v.gateway.service.filters;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.getunleash.Unleash;
import io.getunleash.variant.Variant;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.v.commons.enums.FeatureFlags.SERVER_DOWN;

@Slf4j
@Component
@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE + 2)
public class ServerDownWebFilter implements WebFilter {
    private final Unleash unleash;
    private final ObjectMapper objectMapper;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange,
                             @NonNull WebFilterChain chain) {
        log.info(
                "Incoming Request: [{}] {} | User-Agent: {}",
                exchange.getRequest().getMethod().name(),
                exchange.getRequest().getURI().getPath(),
                exchange.getRequest().getHeaders().getFirst(HttpHeaders.USER_AGENT)
        );
        Variant variant = unleash.getVariant(SERVER_DOWN.name());
        if (variant.isEnabled()) {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
            Map<String, String> body = new HashMap<>();
            body.put("message", "Service Unavailable");
            if (variant.getPayload().isPresent()) {
                body.put("reason", variant.getPayload().get().getValue());
            } else {
                body.put("reason", "Unknown");
            }
            byte[] bytes;
            try {
                bytes = objectMapper.writeValueAsBytes(body);
            } catch (JsonProcessingException ex) {
                bytes = "{\"message\":\"Service Unavailable\"}".getBytes(StandardCharsets.UTF_8);
            }
            return response.writeWith(Mono.just(response.bufferFactory().wrap(bytes)));
        }
        return chain.filter(exchange);
    }
}
