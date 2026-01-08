package org.v.commons.config;

import feign.RequestInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.v.commons.utils.InternalTokenUtility;

import static org.v.commons.constants.HeadersCookies.X_INTERNAL_TOKEN_HEADER;

@Configuration
public class FeignConfig {
    @Bean
    public RequestInterceptor internalTokenInterceptor(InternalTokenUtility internalTokenUtility) {
        return template -> template.header(X_INTERNAL_TOKEN_HEADER, internalTokenUtility.getToken());
    }
}
