// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.domain.port;

import com.instantaccessprovider.arcauth.domain.model.TokenClaims;

/**
 * Signe les revendications sous forme de jeton compact.
 */
public interface TokenSignerPort {

    String sign(TokenClaims claims);
}
