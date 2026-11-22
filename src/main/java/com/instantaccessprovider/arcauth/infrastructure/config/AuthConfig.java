// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.infrastructure.config;

import com.instantaccessprovider.arcauth.application.AuthenticationService;
import com.instantaccessprovider.arcauth.domain.port.LoginAttemptLimiterPort;
import com.instantaccessprovider.arcauth.domain.port.PublicKeySetPort;
import com.instantaccessprovider.arcauth.domain.port.TokenSignerPort;
import com.instantaccessprovider.arcauth.domain.port.UserAuthenticatorPort;
import com.instantaccessprovider.arcauth.domain.service.RoleMapper;
import com.instantaccessprovider.arcauth.infrastructure.jwt.NimbusJwtSigner;
import com.instantaccessprovider.arcauth.infrastructure.jwt.RsaKeys;
import com.instantaccessprovider.arcauth.infrastructure.ldap.LdapUserAuthenticator;
import com.instantaccessprovider.arcauth.infrastructure.limiter.InMemoryLoginAttemptLimiter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.LdapContextSource;

import java.nio.file.Path;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.util.List;
import java.util.Map;

/**
 * Assemble les ports du domaine et leurs adapters.
 */
@Configuration
@EnableConfigurationProperties(AuthProperties.class)
public class AuthConfig {

    private static final Logger LOG = LoggerFactory.getLogger(AuthConfig.class);

    private static final String LDAP_TIMEOUT_MS = "5000";

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    LdapContextSource ldapContextSource(AuthProperties properties) {
        AuthProperties.Ldap ldap = properties.ldap();
        LdapContextSource source = new LdapContextSource();
        source.setUrl(ldap.url());
        if (ldap.managerDn() != null && !ldap.managerDn().isBlank()) {
            source.setUserDn(ldap.managerDn());
            source.setPassword(ldap.managerPassword());
        } else {
            LOG.warn("Aucun compte de service LDAP configuré : recherche en accès anonyme");
            source.setAnonymousReadOnly(true);
        }
        source.setBaseEnvironmentProperties(Map.of(
                "com.sun.jndi.ldap.connect.timeout", LDAP_TIMEOUT_MS,
                "com.sun.jndi.ldap.read.timeout", LDAP_TIMEOUT_MS));
        source.afterPropertiesSet();
        return source;
    }

    @Bean
    UserAuthenticatorPort userAuthenticator(LdapContextSource contextSource, AuthProperties properties) {
        AuthProperties.Ldap ldap = properties.ldap();
        return new LdapUserAuthenticator(contextSource, ldap.userSearchBase(), ldap.userSearchFilter(),
                ldap.groupSearchBase());
    }

    @Bean
    NimbusJwtSigner jwtSigner(AuthProperties properties) {
        AuthProperties.Jwt jwt = properties.jwt();
        RSAPrivateCrtKey privateKey;
        if (jwt.privateKeyPath() == null || jwt.privateKeyPath().isBlank()) {
            LOG.warn("Aucune clé de signature fournie (ARC_AUTH_JWT_PRIVATE_KEY_PATH) : clé éphémère générée. "
                    + "Les jetons n'y survivent pas à un redémarrage ; à réserver à la démonstration.");
            privateKey = RsaKeys.generate();
        } else {
            privateKey = RsaKeys.loadPrivateKey(Path.of(jwt.privateKeyPath()));
        }
        List<RSAPublicKey> additional = jwt.additionalPublicKeyPaths() == null
                ? List.of()
                : jwt.additionalPublicKeyPaths().stream()
                        .filter(p -> !p.isBlank())
                        .map(p -> RsaKeys.loadPublicKey(Path.of(p.trim())))
                        .toList();
        return new NimbusJwtSigner(privateKey, jwt.keyId(), additional);
    }

    @Bean
    LoginAttemptLimiterPort loginAttemptLimiter(AuthProperties properties, Clock clock) {
        AuthProperties.RateLimit limit = properties.rateLimit();
        return new InMemoryLoginAttemptLimiter(limit.maxFailuresPerAddress(), limit.maxFailuresPerIdentifier(),
                limit.window(), clock);
    }

    @Bean
    RoleMapper roleMapper(AuthProperties properties) {
        AuthProperties.Roles roles = properties.roles();
        return new RoleMapper(roles.adminGroup(), roles.publisherGroup(), roles.readerGroup());
    }

    @Bean
    AuthenticationService authenticationService(UserAuthenticatorPort authenticator,
                                                TokenSignerPort signer,
                                                PublicKeySetPort publicKeys,
                                                LoginAttemptLimiterPort limiter,
                                                RoleMapper roleMapper,
                                                Clock clock,
                                                AuthProperties properties) {
        AuthProperties.Jwt jwt = properties.jwt();
        return new AuthenticationService(authenticator, signer, publicKeys, limiter, roleMapper, clock,
                jwt.issuer(), jwt.audience(), jwt.ttl());
    }
}
