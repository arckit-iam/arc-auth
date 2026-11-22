// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.application;

import com.instantaccessprovider.arcauth.domain.exception.InvalidCredentialsException;
import com.instantaccessprovider.arcauth.domain.exception.TooManyAttemptsException;
import com.instantaccessprovider.arcauth.domain.model.AccessToken;
import com.instantaccessprovider.arcauth.domain.model.AttemptKey;
import com.instantaccessprovider.arcauth.domain.model.AuthenticatedUser;
import com.instantaccessprovider.arcauth.domain.model.TokenClaims;
import com.instantaccessprovider.arcauth.domain.port.LoginAttemptLimiterPort;
import com.instantaccessprovider.arcauth.domain.port.PublicKeySetPort;
import com.instantaccessprovider.arcauth.domain.port.TokenSignerPort;
import com.instantaccessprovider.arcauth.domain.port.UserAuthenticatorPort;
import com.instantaccessprovider.arcauth.domain.service.RoleMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AuthenticationServiceTest {

    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    private final UserAuthenticatorPort authenticator = mock(UserAuthenticatorPort.class);
    private final TokenSignerPort signer = mock(TokenSignerPort.class);
    private final PublicKeySetPort publicKeys = mock(PublicKeySetPort.class);
    private final LoginAttemptLimiterPort limiter = mock(LoginAttemptLimiterPort.class);

    private AuthenticationService service;

    @BeforeEach
    void setUp() {
        service = new AuthenticationService(authenticator, signer, publicKeys, limiter,
                new RoleMapper("arc-admins", "arc-publishers", "arc-readers"),
                Clock.fixed(NOW, ZoneOffset.UTC), "https://arc-auth.test", "arc", Duration.ofMinutes(15));
        when(signer.sign(any())).thenReturn("signed.jwt.value");
    }

    @Test
    void issuesTokenWithRolesFromGroups() {
        when(authenticator.authenticate("alice", "pw"))
                .thenReturn(Optional.of(new AuthenticatedUser("alice", "Alice Martin", Set.of("arc-admins", "arc-readers"))));

        AccessToken token = service.issueToken("alice", "pw", "10.0.0.1");

        assertThat(token.value()).isEqualTo("signed.jwt.value");
        assertThat(token.expiresInSeconds()).isEqualTo(900);

        ArgumentCaptor<TokenClaims> captor = ArgumentCaptor.forClass(TokenClaims.class);
        verify(signer).sign(captor.capture());
        TokenClaims claims = captor.getValue();
        assertThat(claims.issuer()).isEqualTo("https://arc-auth.test");
        assertThat(claims.audience()).isEqualTo("arc");
        assertThat(claims.subject()).isEqualTo("alice");
        assertThat(claims.name()).isEqualTo("Alice Martin");
        assertThat(claims.roles()).containsExactly("ARC_ADMIN", "ARC_READER");
        assertThat(claims.issuedAt()).isEqualTo(NOW);
        assertThat(claims.notBefore()).isEqualTo(NOW);
        assertThat(claims.expiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(15)));
        assertThat(claims.tokenId()).isNotBlank();
        verify(limiter).reset(AttemptKey.ofIdentifier("alice"));
    }

    @Test
    void rejectsWrongPasswordAndCountsFailures() {
        when(authenticator.authenticate("alice", "bad")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.issueToken("alice", "bad", "10.0.0.1"))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(limiter).recordFailure(AttemptKey.ofAddress("10.0.0.1"));
        verify(limiter).recordFailure(AttemptKey.ofIdentifier("alice"));
        verify(signer, never()).sign(any());
    }

    @Test
    void neverSendsBlankCredentialsToTheDirectory() {
        assertThatThrownBy(() -> service.issueToken("alice", "", "10.0.0.1"))
                .isInstanceOf(InvalidCredentialsException.class);
        assertThatThrownBy(() -> service.issueToken("alice", null, "10.0.0.1"))
                .isInstanceOf(InvalidCredentialsException.class);
        assertThatThrownBy(() -> service.issueToken(" ", "pw", "10.0.0.1"))
                .isInstanceOf(InvalidCredentialsException.class);

        verifyNoInteractions(authenticator);
        verifyNoInteractions(signer);
    }

    @Test
    void rejectsUserWithoutArcRole() {
        when(authenticator.authenticate("carl", "pw"))
                .thenReturn(Optional.of(new AuthenticatedUser("carl", "Carl", Set.of("finance"))));

        assertThatThrownBy(() -> service.issueToken("carl", "pw", "10.0.0.1"))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(signer, never()).sign(any());
    }

    @Test
    void refusesWithoutQueryingDirectoryWhenAddressIsBlocked() {
        when(limiter.isBlocked(AttemptKey.ofAddress("10.0.0.1"))).thenReturn(true);

        assertThatThrownBy(() -> service.issueToken("alice", "pw", "10.0.0.1"))
                .isInstanceOf(TooManyAttemptsException.class);

        verify(authenticator, never()).authenticate(anyString(), anyString());
    }

    @Test
    void refusesWhenIdentifierIsBlocked() {
        when(limiter.isBlocked(AttemptKey.ofIdentifier("alice"))).thenReturn(true);

        assertThatThrownBy(() -> service.issueToken("Alice", "pw", "10.0.0.2"))
                .isInstanceOf(TooManyAttemptsException.class);

        verify(authenticator, never()).authenticate(anyString(), anyString());
    }
}
