// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.domain.exception;

/**
 * Identifiants refusés. Le message reste volontairement générique : il ne distingue pas
 * un identifiant inconnu d'un mot de passe erroné.
 */
public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException() {
        super("Identifiants invalides");
    }
}
