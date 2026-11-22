// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.infrastructure.jwt;

import com.instantaccessprovider.arcauth.domain.model.PublicKeyDescriptor;
import com.instantaccessprovider.arcauth.domain.model.TokenClaims;
import com.instantaccessprovider.arcauth.domain.port.PublicKeySetPort;
import com.instantaccessprovider.arcauth.domain.port.TokenSignerPort;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Signe les jetons en RS256 et publie les clés publiques actives : celle qui signe,
 * plus les clés supplémentaires utilisées pendant une rotation.
 */
public class NimbusJwtSigner implements TokenSignerPort, PublicKeySetPort {

    private final RSASSASigner signer;
    private final String keyId;
    private final List<PublicKeyDescriptor> publicKeys;

    /**
     * @param privateKey           clé de signature (2048 bits minimum)
     * @param keyId                {@code kid} ; si vide, l'empreinte SHA-256 de la clé publique
     * @param additionalPublicKeys clés publiques à publier en plus, le temps d'une rotation
     */
    public NimbusJwtSigner(RSAPrivateCrtKey privateKey, String keyId, List<RSAPublicKey> additionalPublicKeys) {
        if (privateKey.getModulus().bitLength() < RsaKeys.MIN_KEY_BITS) {
            throw new IllegalArgumentException("La clé RSA doit faire au moins " + RsaKeys.MIN_KEY_BITS + " bits");
        }
        this.signer = new RSASSASigner(privateKey);
        RSAPublicKey publicKey = RsaKeys.publicKeyOf(privateKey);
        this.keyId = keyId == null || keyId.isBlank() ? thumbprint(publicKey) : keyId;

        List<PublicKeyDescriptor> keys = new ArrayList<>();
        keys.add(describe(publicKey, this.keyId));
        for (RSAPublicKey extra : additionalPublicKeys) {
            PublicKeyDescriptor descriptor = describe(extra, thumbprint(extra));
            if (keys.stream().noneMatch(k -> k.keyId().equals(descriptor.keyId()))) {
                keys.add(descriptor);
            }
        }
        this.publicKeys = List.copyOf(keys);
    }

    @Override
    public String sign(TokenClaims claims) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(claims.issuer())
                .subject(claims.subject())
                .audience(claims.audience())
                .issueTime(Date.from(claims.issuedAt()))
                .notBeforeTime(Date.from(claims.notBefore()))
                .expirationTime(Date.from(claims.expiresAt()))
                .jwtID(claims.tokenId())
                .claim("roles", claims.roles());
        if (claims.name() != null && !claims.name().isBlank()) {
            builder.claim("name", claims.name());
        }

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .keyID(keyId)
                .build();
        SignedJWT jwt = new SignedJWT(header, builder.build());
        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw new IllegalStateException("Signature du jeton impossible", e);
        }
        return jwt.serialize();
    }

    @Override
    public List<PublicKeyDescriptor> publicKeys() {
        return publicKeys;
    }

    private static PublicKeyDescriptor describe(RSAPublicKey key, String keyId) {
        RSAKey jwk = new RSAKey.Builder(key).keyID(keyId).build();
        return new PublicKeyDescriptor(keyId, JWSAlgorithm.RS256.getName(),
                jwk.getModulus().toString(), jwk.getPublicExponent().toString());
    }

    private static String thumbprint(RSAPublicKey key) {
        try {
            return new RSAKey.Builder(key).build().computeThumbprint().toString();
        } catch (JOSEException e) {
            throw new IllegalStateException("Calcul de l'empreinte de clé impossible", e);
        }
    }
}
