// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.domain.model;

import java.time.Instant;
import java.util.List;

/**
 * Revendications du jeton à signer.
 *
 * @param issuer    émetteur ({@code iss})
 * @param subject   identifiant de l'utilisateur ({@code sub})
 * @param audience  audience ({@code aud})
 * @param issuedAt  émission ({@code iat})
 * @param notBefore début de validité ({@code nbf})
 * @param expiresAt expiration ({@code exp})
 * @param tokenId   identifiant unique du jeton ({@code jti})
 * @param name      nom complet ({@code name}), éventuellement nul
 * @param roles     rôles ARC ({@code roles})
 */
public record TokenClaims(
        String issuer,
        String subject,
        String audience,
        Instant issuedAt,
        Instant notBefore,
        Instant expiresAt,
        String tokenId,
        String name,
        List<String> roles) {

    public TokenClaims {
        roles = roles == null ? List.of() : List.copyOf(roles);
    }
}
