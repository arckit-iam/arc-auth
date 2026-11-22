// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.domain.model;

import java.util.Set;

/**
 * Utilisateur dont l'annuaire a validé le mot de passe.
 *
 * @param username    identifiant canonique (attribut {@code uid} de l'annuaire)
 * @param displayName nom complet (attribut {@code cn}), éventuellement nul
 * @param groups      noms des groupes dont l'utilisateur est membre
 */
public record AuthenticatedUser(String username, String displayName, Set<String> groups) {

    public AuthenticatedUser {
        groups = groups == null ? Set.of() : Set.copyOf(groups);
    }
}
