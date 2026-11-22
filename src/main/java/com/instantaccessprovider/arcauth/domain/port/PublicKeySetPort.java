// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.domain.port;

import com.instantaccessprovider.arcauth.domain.model.PublicKeyDescriptor;

import java.util.List;

/**
 * Fournit les clés publiques actives, permettant aux services protégés de vérifier les jetons.
 */
public interface PublicKeySetPort {

    List<PublicKeyDescriptor> publicKeys();
}
