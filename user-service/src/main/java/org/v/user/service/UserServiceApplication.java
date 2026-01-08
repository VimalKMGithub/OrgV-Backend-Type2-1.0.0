package org.v.user.service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.cloud.openfeign.EnableFeignClients;

import java.util.TimeZone;

@SpringBootApplication(scanBasePackages = {
        "org.v.user.service",
        "org.v.commons"
})
@ConfigurationPropertiesScan
@EnableFeignClients(basePackages = "org.v.commons.clients")
public class UserServiceApplication {
    static void main(String[] args) {
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        SpringApplication.run(UserServiceApplication.class, args);
    }
}
