package org.v.gateway.service.filters;

import org.jspecify.annotations.NonNull;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import static org.v.commons.constants.HeadersCookies.CSRF_TOKEN_COOKIE;
import static org.v.commons.constants.HeadersCookies.X_CSRF_TOKEN_HEADER;
import static org.v.gateway.service.constants.PublicEndpoints.PUBLIC_GATEWAY_ENDPOINTS_SET;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class CsrfTokenValidatorWebFilter implements WebFilter {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, @NonNull WebFilterChain chain) {
        if (PUBLIC_GATEWAY_ENDPOINTS_SET.contains(exchange.getRequest().getURI().getPath())) {
            return chain.filter(exchange);
        }
        HttpMethod method = exchange.getRequest().getMethod();
        if (method == HttpMethod.GET || method == HttpMethod.HEAD || method == HttpMethod.OPTIONS) {
            return chain.filter(exchange);
        }
        if (exchange.getRequest().getHeaders().getOrigin() == null) {
            return chain.filter(exchange);
        }
        HttpCookie cookie = exchange.getRequest().getCookies().getFirst(CSRF_TOKEN_COOKIE);
        String header = exchange.getRequest().getHeaders().getFirst(X_CSRF_TOKEN_HEADER);
        if (cookie == null || !cookie.getValue().equals(header)) {
            exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
            return exchange.getResponse().setComplete();
        }
        return chain.filter(exchange);
    }
}
