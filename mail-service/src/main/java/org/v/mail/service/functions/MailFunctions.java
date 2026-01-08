package org.v.mail.service.functions;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.v.commons.dtos.MailDto;
import org.v.commons.encryptordecryptors.AesRandomEncryptorDecryptor;
import org.v.mail.service.services.MailService;

import java.util.function.Consumer;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class MailFunctions {
    private final MailService mailService;
    private final AesRandomEncryptorDecryptor aesRandomEncryptorDecryptor;

    @Bean
    public Consumer<MailDto> consumeUserServiceMail() {
        return mailDto -> {
            try {
                handleMail("user-service", mailDto);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        };
    }

    @Bean
    public Consumer<MailDto> consumeAuthServiceMail() {
        return mailDto -> {
            try {
                handleMail("auth-service", mailDto);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        };
    }

    private void handleMail(String source,
                            MailDto mailDto) throws Exception {
        String to = aesRandomEncryptorDecryptor.decrypt(mailDto.getTo());
        String subject = aesRandomEncryptorDecryptor.decrypt(mailDto.getSubject());
        String text = aesRandomEncryptorDecryptor.decrypt(mailDto.getText());
        log.info("Received MailDto from {}: to={}, subject={}", source, to, subject);
        mailService.sendMail(to, subject, text);
    }
}
