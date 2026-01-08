package org.v.gateway.service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.cloud.openfeign.EnableFeignClients;

import java.util.TimeZone;

@SpringBootApplication(scanBasePackages = {
        "org.v.gateway.service",
        "org.v.commons"
})
@ConfigurationPropertiesScan
@EnableFeignClients(basePackages = "org.v.commons.clients")
public class GatewayServiceApplication {
    static void main(String[] args) {
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        SpringApplication.run(GatewayServiceApplication.class, args);
    }
}
