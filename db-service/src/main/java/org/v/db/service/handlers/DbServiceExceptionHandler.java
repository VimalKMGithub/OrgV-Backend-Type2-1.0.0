package org.v.db.service.handlers;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.v.commons.utils.GlobalExceptionHandlerUtility;

import java.util.Map;

@RestControllerAdvice
public class DbServiceExceptionHandler {
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGenericException(Exception ex) {
        return GlobalExceptionHandlerUtility.handleGenericException(ex);
    }
}
