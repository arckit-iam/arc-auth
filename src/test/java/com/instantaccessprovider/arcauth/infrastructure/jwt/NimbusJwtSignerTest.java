// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.infrastructure.jwt;

import com.instantaccessprovider.arcauth.domain.model.PublicKeyDescriptor;
import com.instantaccessprovider.arcauth.domain.model.TokenClaims;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NimbusJwtSignerTest {

    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    private static final TokenClaims CLAIMS = new TokenClaims("https://arc-auth.test", "alice", "arc",
            NOW, NOW, NOW.plusSeconds(900), "jti-1", "Alice Martin", List.of("ARC_ADMIN", "ARC_READER"));

    @Test
    void signsRs256TokenVerifiableWithPublishedKey() throws Exception {
        NimbusJwtSigner signer = new NimbusJwtSigner(RsaKeys.generate(), null, List.of());

        SignedJWT jwt = SignedJWT.parse(signer.sign(CLAIMS));

        PublicKeyDescriptor published = signer.publicKeys().get(0);
        RSAKey jwk = new RSAKey.Builder(new Base64URL(published.modulus()), new Base64URL(published.exponent()))
                .build();
        assertThat(jwt.verify(new RSASSAVerifier(jwk))).isTrue();
        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
        assertThat(jwt.getHeader().getKeyID()).isEqualTo(published.keyId());
        assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo("https://arc-auth.test");
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("alice");
        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("arc");
        assertThat(jwt.getJWTClaimsSet().getJWTID()).isEqualTo("jti-1");
        assertThat(jwt.getJWTClaimsSet().getStringClaim("name")).isEqualTo("Alice Martin");
        assertThat(jwt.getJWTClaimsSet().getStringListClaim("roles")).containsExactly("ARC_ADMIN", "ARC_READER");
        assertThat(jwt.getJWTClaimsSet().getIssueTime().toInstant()).isEqualTo(NOW);
        assertThat(jwt.getJWTClaimsSet().getNotBeforeTime().toInstant()).isEqualTo(NOW);
        assertThat(jwt.getJWTClaimsSet().getExpirationTime().toInstant()).isEqualTo(NOW.plusSeconds(900));
    }

    @Test
    void usesConfiguredKeyId() throws Exception {
        NimbusJwtSigner signer = new NimbusJwtSigner(RsaKeys.generate(), "key-2026", List.of());

        assertThat(SignedJWT.parse(signer.sign(CLAIMS)).getHeader().getKeyID()).isEqualTo("key-2026");
        assertThat(signer.publicKeys()).extracting(PublicKeyDescriptor::keyId).containsExactly("key-2026");
    }

    @Test
    void publishesAdditionalKeysDuringRotation() throws Exception {
        RSAPublicKey previous = RsaKeys.publicKeyOf(RsaKeys.generate());

        NimbusJwtSigner signer = new NimbusJwtSigner(RsaKeys.generate(), "new", List.of(previous));

        assertThat(signer.publicKeys()).hasSize(2);
        assertThat(signer.publicKeys().get(0).keyId()).isEqualTo("new");
        assertThat(SignedJWT.parse(signer.sign(CLAIMS)).getHeader().getKeyID()).isEqualTo("new");
    }

    @Test
    void rejectsKeysSmallerThan2048Bits() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        RSAPrivateCrtKey weak = (RSAPrivateCrtKey) generator.generateKeyPair().getPrivate();

        assertThatThrownBy(() -> new NimbusJwtSigner(weak, null, List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("2048");
    }

    @Test
    void loadsKeysFromPemFiles(@TempDir Path dir) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        Path privatePem = dir.resolve("private.pem");
        Path publicPem = dir.resolve("public.pem");
        Files.writeString(privatePem, pem("PRIVATE KEY", pair.getPrivate().getEncoded()));
        Files.writeString(publicPem, pem("PUBLIC KEY", pair.getPublic().getEncoded()));

        RSAPrivateCrtKey loadedPrivate = RsaKeys.loadPrivateKey(privatePem);
        RSAPublicKey loadedPublic = RsaKeys.loadPublicKey(publicPem);

        assertThat(loadedPrivate.getEncoded()).isEqualTo(pair.getPrivate().getEncoded());
        assertThat(loadedPublic).isEqualTo(pair.getPublic());
    }

    @Test
    void rejectsPkcs1PrivateKey(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("rsa.pem");
        Files.writeString(file, pem("RSA PRIVATE KEY", new byte[] {1, 2, 3}));

        assertThatThrownBy(() -> RsaKeys.loadPrivateKey(file))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("PKCS#8");
    }

    private static String pem(String type, byte[] der) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der)
                + "\n-----END " + type + "-----\n";
    }
}
