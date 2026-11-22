// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.domain.model;

/**
 * Clé de comptage des échecs d'authentification.
 *
 * @param type  nature de la clé
 * @param value adresse source ou identifiant, selon la nature
 */
public record AttemptKey(Type type, String value) {

    public enum Type {
        SOURCE_ADDRESS,
        IDENTIFIER
    }

    public static AttemptKey ofAddress(String address) {
        return new AttemptKey(Type.SOURCE_ADDRESS, address == null ? "" : address);
    }

    public static AttemptKey ofIdentifier(String identifier) {
        return new AttemptKey(Type.IDENTIFIER, identifier == null ? "" : identifier.trim().toLowerCase(java.util.Locale.ROOT));
    }
}
