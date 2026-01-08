package org.v.mail.service.configs;

import org.springframework.context.annotation.Configuration;
import org.springframework.retry.annotation.EnableRetry;

@EnableRetry
@Configuration
public class MailServiceRetryConfig {
}
