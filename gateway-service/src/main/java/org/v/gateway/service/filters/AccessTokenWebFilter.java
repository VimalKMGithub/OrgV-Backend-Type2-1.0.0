package org.v.gateway.service.filters;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import feign.FeignException;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.v.commons.clients.AuthServiceClient;
import org.v.commons.dtos.AccessTokenRequestDto;
import org.v.commons.utils.InternalTokenUtility;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.v.commons.constants.HeadersCookies.*;
import static org.v.gateway.service.constants.PublicEndpoints.PUBLIC_ENDPOINTS_SET;
import static org.v.gateway.service.constants.PublicEndpoints.PUBLIC_GATEWAY_ENDPOINTS_SET;

@Component
@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE + 3)
public class AccessTokenWebFilter implements WebFilter {
    private final AuthServiceClient authServiceClient;
    private final ObjectMapper objectMapper;
    private final InternalTokenUtility internalTokenUtility;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange,
                             @NonNull WebFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        if (PUBLIC_GATEWAY_ENDPOINTS_SET.contains(path)) {
            return chain.filter(exchange);
        }
        if (PUBLIC_ENDPOINTS_SET.contains(path)) {
            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header(X_INTERNAL_TOKEN_HEADER, internalTokenUtility.getToken())
                    .build();
            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        }
        HttpCookie cookie = exchange.getRequest().getCookies().getFirst(ACCESS_TOKEN_COOKIE);
        String accessTokenCookie = cookie != null ? cookie.getValue() : null;
        if (accessTokenCookie != null) {
            return Mono.fromCallable(() -> authServiceClient.verifyToken(
                            new AccessTokenRequestDto(accessTokenCookie),
                            exchange.getRequest().getHeaders().getFirst(USER_AGENT_HEADER),
                            exchange.getRequest().getHeaders().getFirst(X_DEVICE_ID_HEADER)
                    ))
                    .subscribeOn(Schedulers.boundedElastic())
                    .flatMap(authentication -> {
                        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                                .header(X_USER_ID_HEADER, authentication.getUserId())
                                .header(X_USERNAME_HEADER, authentication.getUsername())
                                .header(X_EMAIL_HEADER, authentication.getEmail())
                                .header(X_REAL_EMAIL_HEADER, authentication.getRealEmail())
                                .header(X_MFA_ENABLED_HEADER, String.valueOf(authentication.isMfaEnabled()))
                                .header(X_MFA_METHODS_HEADER, authentication.getMfaMethods())
                                .header(X_AUTHORITIES_HEADER, authentication.getAuthorities())
                                .header(X_EMAILS_FROM_EXTERNAL_IDENTITIES_HEADER, authentication.getEmailsFromExternalIdentities())
                                .header(X_INTERNAL_TOKEN_HEADER, internalTokenUtility.getToken())
                                .build();
                        return chain.filter(exchange.mutate().request(mutatedRequest).build());
                    })
                    .onErrorResume(ex -> unauthorized(exchange, ex));
        }
        return unauthorized(exchange, new Exception("Invalid access token"));
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, Throwable cause) {
        ServerHttpResponse response = exchange.getResponse();
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        String message = "Unauthorized";
        String error = "Unauthorized";
        if (cause instanceof FeignException feignEx) {
            int rawStatus = feignEx.status();
            status = HttpStatus.resolve(rawStatus) != null
                    ? HttpStatus.valueOf(rawStatus)
                    : HttpStatus.INTERNAL_SERVER_ERROR;
            try {
                String content = feignEx.contentUTF8();
                if (content != null && !content.isBlank()) {
                    Map<String, Object> parsed = objectMapper.readValue(content, new TypeReference<>() {
                    });
                    message = parsed.getOrDefault("message", message).toString();
                    error = parsed.getOrDefault("error", error).toString();
                } else {
                    message = feignEx.getMessage();
                }
            } catch (Exception ex) {
                message = feignEx.getMessage();
            }
        } else if (cause != null && cause.getMessage() != null) {
            message = cause.getMessage();
        }
        response.setStatusCode(status);
        Map<String, Object> body = Map.of("error", error, "message", message);
        byte[] bytes;
        try {
            bytes = objectMapper.writeValueAsBytes(body);
        } catch (Exception ex) {
            bytes = ("{\"error\":\"" + error + "\",\"message\":\"" + message + "\"}").getBytes(StandardCharsets.UTF_8);
        }
        return response.writeWith(Mono.just(response.bufferFactory().wrap(bytes)));
    }
}
