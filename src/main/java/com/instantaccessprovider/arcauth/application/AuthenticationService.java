// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.application;

import com.instantaccessprovider.arcauth.domain.exception.InvalidCredentialsException;
import com.instantaccessprovider.arcauth.domain.exception.TooManyAttemptsException;
import com.instantaccessprovider.arcauth.domain.model.AccessToken;
import com.instantaccessprovider.arcauth.domain.model.AttemptKey;
import com.instantaccessprovider.arcauth.domain.model.AuthenticatedUser;
import com.instantaccessprovider.arcauth.domain.model.PublicKeyDescriptor;
import com.instantaccessprovider.arcauth.domain.model.Role;
import com.instantaccessprovider.arcauth.domain.model.TokenClaims;
import com.instantaccessprovider.arcauth.domain.port.LoginAttemptLimiterPort;
import com.instantaccessprovider.arcauth.domain.port.PublicKeySetPort;
import com.instantaccessprovider.arcauth.domain.port.TokenSignerPort;
import com.instantaccessprovider.arcauth.domain.port.UserAuthenticatorPort;
import com.instantaccessprovider.arcauth.domain.service.RoleMapper;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Cas d'usage d'authentification : valide les identifiants dans l'annuaire, déduit les
 * rôles des groupes et émet un jeton signé.
 */
public class AuthenticationService {

    private final UserAuthenticatorPort authenticator;
    private final TokenSignerPort signer;
    private final PublicKeySetPort publicKeys;
    private final LoginAttemptLimiterPort limiter;
    private final RoleMapper roleMapper;
    private final Clock clock;
    private final String issuer;
    private final String audience;
    private final Duration tokenTtl;

    public AuthenticationService(UserAuthenticatorPort authenticator,
                                 TokenSignerPort signer,
                                 PublicKeySetPort publicKeys,
                                 LoginAttemptLimiterPort limiter,
                                 RoleMapper roleMapper,
                                 Clock clock,
                                 String issuer,
                                 String audience,
                                 Duration tokenTtl) {
        this.authenticator = authenticator;
        this.signer = signer;
        this.publicKeys = publicKeys;
        this.limiter = limiter;
        this.roleMapper = roleMapper;
        this.clock = clock;
        this.issuer = issuer;
        this.audience = audience;
        this.tokenTtl = tokenTtl;
    }

    /**
     * Émet un jeton pour les identifiants fournis.
     *
     * @param sourceAddress adresse de l'appelant, utilisée pour la limitation de débit
     * @throws TooManyAttemptsException    si l'adresse ou l'identifiant a trop échoué
     * @throws InvalidCredentialsException si les identifiants sont refusés ou sans rôle ARC
     */
    public AccessToken issueToken(String username, String password, String sourceAddress) {
        AttemptKey addressKey = AttemptKey.ofAddress(sourceAddress);
        AttemptKey identifierKey = AttemptKey.ofIdentifier(username);

        if (limiter.isBlocked(addressKey) || limiter.isBlocked(identifierKey)) {
            throw new TooManyAttemptsException();
        }

        // Un mot de passe vide ne doit jamais atteindre l'annuaire : un bind simple sans mot de passe
        // est traité comme anonyme et réussit.
        Optional<AuthenticatedUser> user = isBlank(username) || isBlank(password)
                ? Optional.empty()
                : authenticator.authenticate(username, password);

        if (user.isEmpty()) {
            limiter.recordFailure(addressKey);
            limiter.recordFailure(identifierKey);
            throw new InvalidCredentialsException();
        }

        List<String> roles = roleMapper.rolesFor(user.get().groups()).stream().map(Role::name).toList();
        if (roles.isEmpty()) {
            throw new InvalidCredentialsException();
        }

        limiter.reset(identifierKey);

        Instant now = clock.instant();
        TokenClaims claims = new TokenClaims(
                issuer,
                user.get().username(),
                audience,
                now,
                now,
                now.plus(tokenTtl),
                UUID.randomUUID().toString(),
                user.get().displayName(),
                roles);
        return new AccessToken(signer.sign(claims), tokenTtl.toSeconds());
    }

    /** Clés publiques actives, pour le JWKS. */
    public List<PublicKeyDescriptor> publicKeys() {
        return publicKeys.publicKeys();
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
