package org.v.commons.filters;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.v.commons.utils.InternalTokenUtility;

import java.io.IOException;
import java.util.Map;

import static org.v.commons.constants.HeadersCookies.X_INTERNAL_TOKEN_HEADER;

@Slf4j
@Component
@RequiredArgsConstructor
public class InternalRequestFilter extends OncePerRequestFilter {
    private final InternalTokenUtility internalTokenUtility;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws IOException {
        try {
            String internalToken = request.getHeader(X_INTERNAL_TOKEN_HEADER);
            if (internalToken != null) {
                String serviceName = internalTokenUtility.verifyInternalToken(internalToken);
                log.info(
                        "Incoming Request: [{}] {} | From Service: {} | User-Agent: {}",
                        request.getMethod(),
                        request.getRequestURI(),
                        serviceName,
                        request.getHeader(HttpHeaders.USER_AGENT)
                );
                filterChain.doFilter(request, response);
            } else {
                throw new Exception("Invalid internal token");
            }
        } catch (Exception ex) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            objectMapper.writeValue(response.getWriter(), Map.of("error", "Unauthorized", "message", ex.getMessage()));
        }
    }
}
