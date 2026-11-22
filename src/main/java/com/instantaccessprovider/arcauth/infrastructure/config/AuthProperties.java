// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.infrastructure.config;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.List;

/**
 * Paramètres du service, préfixe {@code arc.auth} (voir {@code application.yml} pour les
 * variables d'environnement {@code ARC_AUTH_*} associées).
 */
@Validated
@ConfigurationProperties(prefix = "arc.auth")
public record AuthProperties(
        @Valid @NotNull Ldap ldap,
        @Valid @NotNull Jwt jwt,
        @Valid @NotNull Roles roles,
        @Valid @NotNull RateLimit rateLimit) {

    public record Ldap(
            @NotBlank String url,
            String managerDn,
            String managerPassword,
            @NotBlank String userSearchBase,
            @NotBlank String userSearchFilter,
            @NotBlank String groupSearchBase) {
    }

    public record Jwt(
            @NotBlank String issuer,
            @NotBlank String audience,
            @NotNull Duration ttl,
            String privateKeyPath,
            String keyId,
            List<String> additionalPublicKeyPaths) {
    }

    public record Roles(
            @NotBlank String adminGroup,
            @NotBlank String publisherGroup,
            @NotBlank String readerGroup) {
    }

    public record RateLimit(
            @Min(1) int maxFailuresPerAddress,
            @Min(1) int maxFailuresPerIdentifier,
            @NotNull Duration window) {
    }
}
