package org.v.commons.exceptions;

public class SimpleBadRequestException extends RuntimeException {
    public SimpleBadRequestException(String message) {
        super(message);
    }
}
