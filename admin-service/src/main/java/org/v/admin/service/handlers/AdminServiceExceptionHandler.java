package org.v.admin.service.handlers;

import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MissingRequestValueException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import org.v.commons.exceptions.AccessDeniedException;
import org.v.commons.exceptions.ServiceUnavailableException;
import org.v.commons.exceptions.SimpleBadRequestException;
import org.v.commons.utils.GlobalExceptionHandlerUtility;

import java.util.Map;

@RestControllerAdvice
public class AdminServiceExceptionHandler {
    @ExceptionHandler(ServiceUnavailableException.class)
    public ResponseEntity<Map<String, String>> handleServiceUnavailableException(ServiceUnavailableException ex) {
        return GlobalExceptionHandlerUtility.handleServiceUnavailableException(ex);
    }

    @ExceptionHandler(org.v.commons.exceptions.AccessDeniedException.class)
    public ResponseEntity<Map<String, String>> handleAccessDeniedException(AccessDeniedException ex) {
        return GlobalExceptionHandlerUtility.handleAccessDeniedException(ex);
    }

    @ExceptionHandler({
            SimpleBadRequestException.class,
            HttpMessageNotReadableException.class,
            NoResourceFoundException.class,
            MissingRequestValueException.class
    })
    public ResponseEntity<Map<String, String>> handleBadRequestExceptions(Exception ex) {
        return GlobalExceptionHandlerUtility.handleBadRequestExceptions(ex);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(Exception ex) {
        return GlobalExceptionHandlerUtility.handleGenericException(ex);
    }
}
