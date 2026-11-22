// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.infrastructure.web;

import com.instantaccessprovider.arcauth.application.AuthenticationService;
import com.instantaccessprovider.arcauth.domain.model.AccessToken;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Émission des jetons d'accès.
 */
@RestController
public class TokenController {

    private final AuthenticationService authenticationService;

    public TokenController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping(path = "/token", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<TokenResponse> token(@RequestBody TokenRequest request, HttpServletRequest http) {
        AccessToken token = authenticationService.issueToken(
                request.username(), request.password(), http.getRemoteAddr());
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header("Pragma", "no-cache")
                .body(new TokenResponse(token.value(), "Bearer", token.expiresInSeconds()));
    }
}
