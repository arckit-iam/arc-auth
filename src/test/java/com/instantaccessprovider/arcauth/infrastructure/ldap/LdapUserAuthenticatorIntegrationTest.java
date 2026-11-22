// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.infrastructure.ldap;

import com.instantaccessprovider.arcauth.application.AuthenticationService;
import com.instantaccessprovider.arcauth.domain.exception.AuthenticationUnavailableException;
import com.instantaccessprovider.arcauth.domain.exception.InvalidCredentialsException;
import com.instantaccessprovider.arcauth.domain.exception.TooManyAttemptsException;
import com.instantaccessprovider.arcauth.domain.model.AccessToken;
import com.instantaccessprovider.arcauth.domain.model.AuthenticatedUser;
import com.instantaccessprovider.arcauth.domain.model.PublicKeyDescriptor;
import com.instantaccessprovider.arcauth.domain.service.RoleMapper;
import com.instantaccessprovider.arcauth.infrastructure.jwt.NimbusJwtSigner;
import com.instantaccessprovider.arcauth.infrastructure.jwt.RsaKeys;
import com.instantaccessprovider.arcauth.infrastructure.limiter.InMemoryLoginAttemptLimiter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import org.apache.directory.server.core.annotations.ApplyLdifs;
import org.apache.directory.server.core.annotations.ContextEntry;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.ApacheDSTestExtension;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.ldap.core.support.LdapContextSource;

import java.time.Clock;
import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Teste l'adapter LDAP et la chaîne complète (bind, groupes, rôles, jeton signé) sur un
 * Apache DS embarqué.
 */
@ExtendWith(ApacheDSTestExtension.class)
@CreateDS(
        name = "arc-auth",
        partitions = @CreatePartition(
                name = "arc",
                suffix = "dc=arc,dc=local",
                contextEntry = @ContextEntry(entryLdif =
                        "dn: dc=arc,dc=local\n" +
                        "dc: arc\n" +
                        "objectClass: top\n" +
                        "objectClass: domain\n\n")))
@CreateLdapServer(transports = @CreateTransport(protocol = "LDAP"))
@ApplyLdifs({
        "dn: ou=people,dc=arc,dc=local",
        "objectClass: top",
        "objectClass: organizationalUnit",
        "ou: people",
        "",
        "dn: ou=groups,dc=arc,dc=local",
        "objectClass: top",
        "objectClass: organizationalUnit",
        "ou: groups",
        "",
        "dn: uid=alice,ou=people,dc=arc,dc=local",
        "objectClass: top",
        "objectClass: person",
        "objectClass: organizationalPerson",
        "objectClass: inetOrgPerson",
        "uid: alice",
        "cn: Alice Martin",
        "sn: Martin",
        "userPassword: secret-alice",
        "",
        "dn: uid=bob,ou=people,dc=arc,dc=local",
        "objectClass: top",
        "objectClass: person",
        "objectClass: organizationalPerson",
        "objectClass: inetOrgPerson",
        "uid: bob",
        "cn: Bob Durand",
        "sn: Durand",
        "userPassword: secret-bob",
        "",
        "dn: uid=carl,ou=people,dc=arc,dc=local",
        "objectClass: top",
        "objectClass: person",
        "objectClass: organizationalPerson",
        "objectClass: inetOrgPerson",
        "uid: carl",
        "cn: Carl Petit",
        "sn: Petit",
        "userPassword: secret-carl",
        "",
        "dn: uid=dave,ou=people,dc=arc,dc=local",
        "objectClass: top",
        "objectClass: person",
        "objectClass: organizationalPerson",
        "objectClass: inetOrgPerson",
        "uid: dave",
        "cn: Dave Roux",
        "sn: Roux",
        "userPassword: secret-dave",
        "",
        "dn: cn=duplicate-of-bob,ou=people,dc=arc,dc=local",
        "objectClass: top",
        "objectClass: person",
        "objectClass: organizationalPerson",
        "objectClass: inetOrgPerson",
        "uid: bob",
        "cn: duplicate-of-bob",
        "sn: Durand",
        "userPassword: other",
        "",
        "dn: cn=arc-admins,ou=groups,dc=arc,dc=local",
        "objectClass: top",
        "objectClass: groupOfNames",
        "cn: arc-admins",
        "member: uid=alice,ou=people,dc=arc,dc=local",
        "",
        "dn: cn=arc-readers,ou=groups,dc=arc,dc=local",
        "objectClass: top",
        "objectClass: groupOfNames",
        "cn: arc-readers",
        "member: uid=alice,ou=people,dc=arc,dc=local",
        "member: uid=carl,ou=people,dc=arc,dc=local",
        "",
        "dn: cn=finance,ou=groups,dc=arc,dc=local",
        "objectClass: top",
        "objectClass: groupOfNames",
        "cn: finance",
        "member: uid=carl,ou=people,dc=arc,dc=local",
        "member: uid=dave,ou=people,dc=arc,dc=local",
        ""
})
public class LdapUserAuthenticatorIntegrationTest extends AbstractLdapTestUnit {

    private LdapContextSource contextSource;
    private LdapUserAuthenticator authenticator;

    @BeforeEach
    void setUp() {
        contextSource = contextSource(getLdapServer().getPort());
        authenticator = new LdapUserAuthenticator(contextSource,
                "ou=people,dc=arc,dc=local", "(uid={0})", "ou=groups,dc=arc,dc=local");
    }

    @Test
    void authenticatesWithValidPasswordAndReturnsGroups() {
        Optional<AuthenticatedUser> user = authenticator.authenticate("alice", "secret-alice");

        assertThat(user).isPresent();
        assertThat(user.get().username()).isEqualTo("alice");
        assertThat(user.get().displayName()).isEqualTo("Alice Martin");
        assertThat(user.get().groups()).containsExactlyInAnyOrder("arc-admins", "arc-readers");
    }

    @Test
    void identifierMatchIsCaseInsensitiveAndSubjectIsCanonicalUid() {
        Optional<AuthenticatedUser> user = authenticator.authenticate("ALICE", "secret-alice");

        assertThat(user).isPresent();
        assertThat(user.get().username()).isEqualTo("alice");
    }

    @Test
    void rejectsWrongPassword() {
        assertThat(authenticator.authenticate("alice", "wrong")).isEmpty();
    }

    @Test
    void rejectsUnknownUser() {
        assertThat(authenticator.authenticate("nobody", "secret-alice")).isEmpty();
    }

    @Test
    void rejectsFilterInjection() {
        assertThat(authenticator.authenticate("*", "secret-alice")).isEmpty();
        assertThat(authenticator.authenticate("alice)(uid=*", "secret-alice")).isEmpty();
        assertThat(authenticator.authenticate("*)(|(uid=*", "secret-alice")).isEmpty();
    }

    @Test
    void rejectsAmbiguousIdentifier() {
        assertThat(authenticator.authenticate("bob", "secret-bob")).isEmpty();
        assertThat(authenticator.authenticate("bob", "other")).isEmpty();
    }

    @Test
    void returnsAllGroupsOfUser() {
        Optional<AuthenticatedUser> user = authenticator.authenticate("carl", "secret-carl");

        assertThat(user).isPresent();
        assertThat(user.get().groups()).containsExactlyInAnyOrder("arc-readers", "finance");
    }

    @Test
    void reportsUnavailableDirectory() {
        LdapUserAuthenticator unreachable = new LdapUserAuthenticator(contextSource(1),
                "ou=people,dc=arc,dc=local", "(uid={0})", "ou=groups,dc=arc,dc=local");

        assertThatThrownBy(() -> unreachable.authenticate("alice", "secret-alice"))
                .isInstanceOf(AuthenticationUnavailableException.class);
    }

    @Test
    void issuesVerifiableTokenEndToEnd() throws Exception {
        NimbusJwtSigner signer = new NimbusJwtSigner(RsaKeys.generate(), null, java.util.List.of());
        AuthenticationService service = new AuthenticationService(authenticator, signer, signer,
                new InMemoryLoginAttemptLimiter(20, 2, Duration.ofMinutes(5), Clock.systemUTC()),
                new RoleMapper("arc-admins", "arc-publishers", "arc-readers"),
                Clock.systemUTC(), "https://arc-auth.test", "arc", Duration.ofMinutes(15));

        AccessToken token = service.issueToken("alice", "secret-alice", "127.0.0.1");

        SignedJWT jwt = SignedJWT.parse(token.value());
        PublicKeyDescriptor key = service.publicKeys().get(0);
        RSAKey jwk = new RSAKey.Builder(new Base64URL(key.modulus()), new Base64URL(key.exponent())).build();
        assertThat(jwt.verify(new RSASSAVerifier(jwk))).isTrue();
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("alice");
        assertThat(jwt.getJWTClaimsSet().getStringListClaim("roles")).containsExactly("ARC_ADMIN", "ARC_READER");
        assertThat(token.expiresInSeconds()).isEqualTo(900);

        // Un utilisateur sans groupe ARC se voit refuser le jeton, même avec le bon mot de passe.
        assertThatThrownBy(() -> service.issueToken("dave", "secret-dave", "127.0.0.1"))
                .isInstanceOf(InvalidCredentialsException.class);
    }

    @Test
    void blocksAfterRepeatedFailures() {
        AuthenticationService service = new AuthenticationService(authenticator,
                new NimbusJwtSigner(RsaKeys.generate(), null, java.util.List.of()),
                new NimbusJwtSigner(RsaKeys.generate(), null, java.util.List.of()),
                new InMemoryLoginAttemptLimiter(20, 2, Duration.ofMinutes(5), Clock.systemUTC()),
                new RoleMapper("arc-admins", "arc-publishers", "arc-readers"),
                Clock.systemUTC(), "https://arc-auth.test", "arc", Duration.ofMinutes(15));

        for (int i = 0; i < 2; i++) {
            assertThatThrownBy(() -> service.issueToken("alice", "wrong", "127.0.0.1"))
                    .isInstanceOf(InvalidCredentialsException.class);
        }

        // Le bon mot de passe est lui-même refusé une fois le seuil atteint.
        assertThatThrownBy(() -> service.issueToken("alice", "secret-alice", "127.0.0.1"))
                .isInstanceOf(TooManyAttemptsException.class);
    }

    private static LdapContextSource contextSource(int port) {
        LdapContextSource source = new LdapContextSource();
        source.setUrl("ldap://localhost:" + port);
        source.setUserDn("uid=admin,ou=system");
        source.setPassword("secret");
        source.afterPropertiesSet();
        return source;
    }
}
