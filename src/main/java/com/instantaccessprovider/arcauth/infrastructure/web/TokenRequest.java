// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.infrastructure.web;

/**
 * Corps de la requête {@code POST /token}. Le mot de passe n'apparaît pas dans {@code toString()}.
 */
public record TokenRequest(String username, String password) {

    @Override
    public String toString() {
        return "TokenRequest[username=" + username + ", password=***]";
    }
}
