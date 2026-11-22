// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.domain.port;

import com.instantaccessprovider.arcauth.domain.model.AttemptKey;

/**
 * Limite les essais successifs d'authentification, par adresse source et par identifiant.
 */
public interface LoginAttemptLimiterPort {

    /** Indique si la clé a atteint son seuil d'échecs dans la fenêtre courante. */
    boolean isBlocked(AttemptKey key);

    void recordFailure(AttemptKey key);

    void reset(AttemptKey key);
}
