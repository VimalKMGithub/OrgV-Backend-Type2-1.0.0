package org.v.user.service.services;

import lombok.RequiredArgsConstructor;
import org.springframework.cloud.stream.function.StreamBridge;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.v.commons.dtos.MailDto;
import org.v.commons.encryptordecryptors.AesRandomEncryptorDecryptor;
import org.v.commons.enums.MailType;

import static org.v.commons.utils.MailUtility.getEmailText;

@Service
@RequiredArgsConstructor
public class UserServiceMailService {
    private final StreamBridge streamBridge;
    private final AesRandomEncryptorDecryptor aesRandomEncryptorDecryptor;

    @Async
    public void sendEmailAsync(String to,
                               String subject,
                               String value,
                               MailType mailType) throws Exception {
        streamBridge.send(
                "userServiceMailService-out-0",
                new MailDto(
                        aesRandomEncryptorDecryptor.encrypt(to),
                        aesRandomEncryptorDecryptor.encrypt(subject),
                        aesRandomEncryptorDecryptor.encrypt(getEmailText(value, mailType))
                )
        );
    }
}
