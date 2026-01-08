package org.v.admin.service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.cloud.openfeign.EnableFeignClients;

import java.util.TimeZone;

@SpringBootApplication(scanBasePackages = {
        "org.v.admin.service",
        "org.v.commons"
})
@ConfigurationPropertiesScan
@EnableFeignClients(basePackages = "org.v.commons.clients")
public class AdminServiceApplication {
    static void main(String[] args) {
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        SpringApplication.run(AdminServiceApplication.class, args);
    }
}
