// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.infrastructure.web;

import com.instantaccessprovider.arcauth.application.AuthenticationService;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Publication des clés publiques (JWKS, RFC 7517) pour la vérification des jetons.
 */
@RestController
public class JwksController {

    private final AuthenticationService authenticationService;

    public JwksController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @GetMapping(path = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, List<Map<String, String>>>> jwks() {
        List<Map<String, String>> keys = authenticationService.publicKeys().stream()
                .map(k -> Map.of(
                        "kty", "RSA",
                        "use", "sig",
                        "alg", k.algorithm(),
                        "kid", k.keyId(),
                        "n", k.modulus(),
                        "e", k.exponent()))
                .toList();
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePublic())
                .body(Map.of("keys", keys));
    }
}
