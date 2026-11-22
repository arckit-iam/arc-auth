// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.domain.port;

import com.instantaccessprovider.arcauth.domain.exception.AuthenticationUnavailableException;
import com.instantaccessprovider.arcauth.domain.model.AuthenticatedUser;

import java.util.Optional;

/**
 * Vérifie un couple identifiant / mot de passe auprès de l'annuaire.
 */
public interface UserAuthenticatorPort {

    /**
     * @return l'utilisateur et ses groupes si les identifiants sont valides, vide sinon
     * @throws AuthenticationUnavailableException si l'annuaire est injoignable
     */
    Optional<AuthenticatedUser> authenticate(String username, String password);
}
