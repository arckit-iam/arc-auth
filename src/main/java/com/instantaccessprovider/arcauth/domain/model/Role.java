// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.domain.model;

/**
 * Rôle applicatif ARC porté par le jeton (claim {@code roles}).
 */
public enum Role {
    ARC_ADMIN,
    ARC_PUBLISHER,
    ARC_READER
}
