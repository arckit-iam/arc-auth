// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.domain.exception;

/**
 * L'annuaire ne peut pas répondre : l'authentification n'est ni acceptée ni refusée.
 */
public class AuthenticationUnavailableException extends RuntimeException {

    public AuthenticationUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
