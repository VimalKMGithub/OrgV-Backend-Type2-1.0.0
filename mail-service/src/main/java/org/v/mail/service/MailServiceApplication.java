package org.v.mail.service;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

import java.util.TimeZone;

@SpringBootApplication(scanBasePackages = {
        "org.v.mail.service",
        "org.v.commons"
})
@ConfigurationPropertiesScan
public class MailServiceApplication {
    static void main(String[] args) {
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        SpringApplication.run(MailServiceApplication.class, args);
    }
}
