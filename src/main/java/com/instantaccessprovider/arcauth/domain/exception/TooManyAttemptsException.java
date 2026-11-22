// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.domain.exception;

/**
 * Trop d'échecs successifs pour cette adresse source ou cet identifiant.
 */
public class TooManyAttemptsException extends RuntimeException {

    public TooManyAttemptsException() {
        super("Trop de tentatives");
    }
}
