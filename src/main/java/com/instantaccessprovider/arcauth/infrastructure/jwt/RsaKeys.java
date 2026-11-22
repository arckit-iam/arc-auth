// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.infrastructure.jwt;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Chargement et génération des clés RSA. Les clés PEM attendues sont au format PKCS#8
 * (clé privée, en-tête {@code BEGIN PRIVATE KEY}) et X.509 SPKI (clé publique,
 * en-tête {@code BEGIN PUBLIC KEY}).
 */
public final class RsaKeys {

    static final int MIN_KEY_BITS = 2048;

    private RsaKeys() {
    }

    public static RSAPrivateCrtKey loadPrivateKey(Path path) {
        String pem = read(path);
        if (!pem.contains("BEGIN PRIVATE KEY")) {
            throw new IllegalArgumentException("La clé privée " + path
                    + " doit être au format PKCS#8 (en-tête BEGIN PRIVATE KEY, non chiffrée). "
                    + "Conversion : openssl pkcs8 -topk8 -nocrypt -in cle.pem -out cle-pkcs8.pem");
        }
        try {
            var key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decode(pem)));
            if (key instanceof RSAPrivateCrtKey crt) {
                return crt;
            }
            throw new IllegalArgumentException("La clé privée " + path + " n'est pas une clé RSA complète");
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Clé privée illisible : " + path, e);
        }
    }

    public static RSAPublicKey loadPublicKey(Path path) {
        String pem = read(path);
        if (!pem.contains("BEGIN PUBLIC KEY")) {
            throw new IllegalArgumentException("La clé publique " + path
                    + " doit être au format X.509 (en-tête BEGIN PUBLIC KEY)");
        }
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decode(pem)));
        } catch (GeneralSecurityException | ClassCastException e) {
            throw new IllegalArgumentException("Clé publique illisible : " + path, e);
        }
    }

    public static RSAPrivateCrtKey generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(MIN_KEY_BITS);
            KeyPair pair = generator.generateKeyPair();
            return (RSAPrivateCrtKey) pair.getPrivate();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Génération de la clé RSA impossible", e);
        }
    }

    static RSAPublicKey publicKeyOf(RSAPrivateCrtKey privateKey) {
        try {
            BigInteger modulus = privateKey.getModulus();
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new RSAPublicKeySpec(modulus, privateKey.getPublicExponent()));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Dérivation de la clé publique impossible", e);
        }
    }

    private static String read(Path path) {
        try {
            return Files.readString(path, StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new IllegalArgumentException("Fichier de clé illisible : " + path, e);
        }
    }

    private static byte[] decode(String pem) {
        String body = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }
}
