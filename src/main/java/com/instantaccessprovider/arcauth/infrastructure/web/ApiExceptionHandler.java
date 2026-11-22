// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.infrastructure.web;

import com.instantaccessprovider.arcauth.domain.exception.AuthenticationUnavailableException;
import com.instantaccessprovider.arcauth.domain.exception.InvalidCredentialsException;
import com.instantaccessprovider.arcauth.domain.exception.TooManyAttemptsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * Traduit les erreurs du domaine en réponses HTTP. Les corps d'erreur sont constants :
 * ils ne révèlent ni l'existence d'un compte ni la cause d'un refus.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<Map<String, String>> invalidCredentials() {
        return error(HttpStatus.UNAUTHORIZED, "invalid_credentials");
    }

    @ExceptionHandler(TooManyAttemptsException.class)
    public ResponseEntity<Map<String, String>> tooManyAttempts() {
        return error(HttpStatus.TOO_MANY_REQUESTS, "too_many_attempts");
    }

    @ExceptionHandler(AuthenticationUnavailableException.class)
    public ResponseEntity<Map<String, String>> unavailable(AuthenticationUnavailableException e) {
        LOG.error("Annuaire indisponible", e);
        return error(HttpStatus.SERVICE_UNAVAILABLE, "authentication_unavailable");
    }

    private static ResponseEntity<Map<String, String>> error(HttpStatus status, String code) {
        return ResponseEntity.status(status)
                .header("Cache-Control", "no-store")
                .body(Map.of("error", code));
    }
}
