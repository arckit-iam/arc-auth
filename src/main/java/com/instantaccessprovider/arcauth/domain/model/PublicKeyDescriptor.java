// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.domain.model;

/**
 * Clé publique de vérification des jetons, publiée dans le JWKS.
 *
 * @param keyId     identifiant de clé ({@code kid})
 * @param algorithm algorithme de signature associé (ex. {@code RS256})
 * @param modulus   module RSA, encodé en base64url sans remplissage
 * @param exponent  exposant public RSA, encodé en base64url sans remplissage
 */
public record PublicKeyDescriptor(String keyId, String algorithm, String modulus, String exponent) {
}
