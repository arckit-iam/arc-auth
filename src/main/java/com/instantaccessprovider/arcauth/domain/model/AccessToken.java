// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.domain.model;

/**
 * Jeton d'accès émis.
 *
 * @param value            jeton signé sous forme compacte
 * @param expiresInSeconds durée de validité restante, en secondes
 */
public record AccessToken(String value, long expiresInSeconds) {
}
