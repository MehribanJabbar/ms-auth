package com.example.msauth.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import static com.example.msauth.model.constants.ExceptionConstants.UNEXPECTED_EXCEPTION_CODE;
import static com.example.msauth.model.constants.ExceptionConstants.UNEXPECTED_EXCEPTION_MESSAGE;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;

@Slf4j
@RestControllerAdvice
public class ErrorHandler {
    @ExceptionHandler(Exception.class)
    @ResponseStatus(INTERNAL_SERVER_ERROR)
    public ErrorResponse handle(Exception ex) {
        log.error("Exception: ", ex);
        return new ErrorResponse(UNEXPECTED_EXCEPTION_CODE, UNEXPECTED_EXCEPTION_MESSAGE);
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ErrorResponse> handle(AuthException ex) {
        log.error("AuthException: ", ex);
        return ResponseEntity
                .status(ex.getHttpStatus())
                .body(new ErrorResponse(ex.getCode(), ex.getMessage()));
    }
}
