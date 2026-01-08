package org.v.commons.utils;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.v.commons.exceptions.AccessDeniedException;

import java.util.*;

@Slf4j
public class GlobalExceptionHandlerUtility {
    public static ResponseEntity<Map<String, String>> handleServiceUnavailableException(Exception ex) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of("message", "Service Unavailable", "reason", ex.getMessage()));
    }

    public static ResponseEntity<Map<String, String>> handleAccessDeniedException(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("error", "Forbidden", "message", ex.getMessage()));
    }

    public static ResponseEntity<Map<String, String>> handleBadRequestExceptions(Exception ex) {
        return ResponseEntity.badRequest().body(Map.of("error", "Bad Request", "message", ex.getMessage()));
    }

    public static ResponseEntity<Map<String, Object>> handleGenericException(Exception ex) {
        HashMap<String, Object> errorResponse = new LinkedHashMap<>();
        errorResponse.put("severity", "Error");
        errorResponse.put("message", ex.getMessage());
        HashMap<String, Object> innerErrorData = new LinkedHashMap<>();
        innerErrorData.put("exception", ex.toString());
        innerErrorData.put("stack", formatStackTrace(ex));
        errorResponse.put("innerErrorData", innerErrorData);
        log.error(
                "An unexpected error occurred: {}\n{}",
                ex.getMessage(),
                errorResponse
        );
        return ResponseEntity.internalServerError().body(errorResponse);
    }

    private static List<String> formatStackTrace(Throwable ex) {
        StackTraceElement[] stackTrace = ex.getStackTrace();
        List<String> stackTraceFormatted = new ArrayList<>(stackTrace.length);
        for (StackTraceElement ste : stackTrace) {
            stackTraceFormatted.add(ste.getClassName() + "." +
                    ste.getMethodName() + "(" +
                    ste.getFileName() + ":" +
                    ste.getLineNumber() + ")");
        }
        return stackTraceFormatted;
    }
}
