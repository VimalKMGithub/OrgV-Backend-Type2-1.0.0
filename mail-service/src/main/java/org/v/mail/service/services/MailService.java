package org.v.mail.service.services;

import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MailService {
    private final RetryMailService retryMailService;

    @Async
    public void sendMail(String to,
                         String subject,
                         String text) {
        retryMailService.sendEmail(to, subject, text);
    }
}
