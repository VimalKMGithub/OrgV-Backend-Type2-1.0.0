package org.v.gateway.service.controllers;

import org.springframework.http.ResponseCookie;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

import static org.v.commons.constants.HeadersCookies.CSRF_TOKEN_COOKIE;

@RestController
public class CsrfController {
    @GetMapping("/csrf")
    public Mono<Void> csrf(ServerWebExchange exchange) {
        ResponseCookie cookie = ResponseCookie.from(CSRF_TOKEN_COOKIE, UUID.randomUUID().toString())
                .path("/")
                .sameSite("Lax")
                .httpOnly(false)
                // .secure(true) // enable when HTTPS
                .build();
        exchange.getResponse().addCookie(cookie);
        return Mono.empty();
    }
}
