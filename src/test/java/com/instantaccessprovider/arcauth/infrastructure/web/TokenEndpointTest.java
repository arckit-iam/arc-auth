// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.infrastructure.web;

import com.instantaccessprovider.arcauth.domain.exception.AuthenticationUnavailableException;
import com.instantaccessprovider.arcauth.domain.model.AuthenticatedUser;
import com.instantaccessprovider.arcauth.domain.port.UserAuthenticatorPort;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "ARC_AUTH_JWT_ISSUER=https://arc-auth.test",
        "arc.auth.rate-limit.max-failures-per-identifier=3"
})
@AutoConfigureMockMvc
class TokenEndpointTest {

    @Autowired
    private MockMvc mvc;

    @MockitoBean
    private UserAuthenticatorPort authenticator;

    @Test
    void issuesTokenVerifiableWithPublishedJwks() throws Exception {
        when(authenticator.authenticate("alice", "pw"))
                .thenReturn(Optional.of(new AuthenticatedUser("alice", "Alice Martin", Set.of("arc-publishers"))));

        MvcResult result = mvc.perform(post("/token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"pw\"}"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(900))
                .andReturn();

        String body = result.getResponse().getContentAsString();
        String token = com.jayway.jsonpath.JsonPath.read(body, "$.access_token");

        String jwks = mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        SignedJWT jwt = SignedJWT.parse(token);
        RSAKey key = (RSAKey) JWKSet.parse(jwks).getKeyByKeyId(jwt.getHeader().getKeyID());
        assertThat(key).isNotNull();
        assertThat(jwt.verify(new RSASSAVerifier(key))).isTrue();
        assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo("https://arc-auth.test");
        assertThat(jwt.getJWTClaimsSet().getAudience()).containsExactly("arc");
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("alice");
        assertThat(jwt.getJWTClaimsSet().getStringListClaim("roles")).containsExactly("ARC_PUBLISHER");
    }

    @Test
    void answersUniform401ForUnknownUserAndWrongPassword() throws Exception {
        when(authenticator.authenticate(anyString(), anyString())).thenReturn(Optional.empty());

        String first = mvc.perform(post("/token").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"ghost\",\"password\":\"x\"}"))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();
        String second = mvc.perform(post("/token").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"y\"}"))
                .andExpect(status().isUnauthorized())
                .andReturn().getResponse().getContentAsString();

        assertThat(first).isEqualTo(second).contains("invalid_credentials");
    }

    @Test
    void answers401WhenCredentialsAreMissing() throws Exception {
        mvc.perform(post("/token").contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void answers429AfterRepeatedFailuresForAnIdentifier() throws Exception {
        when(authenticator.authenticate(anyString(), anyString())).thenReturn(Optional.empty());
        String attempt = "{\"username\":\"mallory\",\"password\":\"x\"}";

        for (int i = 0; i < 3; i++) {
            mvc.perform(post("/token").contentType(MediaType.APPLICATION_JSON).content(attempt))
                    .andExpect(status().isUnauthorized());
        }
        mvc.perform(post("/token").contentType(MediaType.APPLICATION_JSON).content(attempt))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.error").value("too_many_attempts"));
    }

    @Test
    void answers503WhenDirectoryIsUnavailable() throws Exception {
        when(authenticator.authenticate("alice", "pw"))
                .thenThrow(new AuthenticationUnavailableException("down", new RuntimeException()));

        mvc.perform(post("/token").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"username\":\"alice\",\"password\":\"pw\"}"))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.error").value("authentication_unavailable"));
    }

    @Test
    void rejectsNonJsonRequests() throws Exception {
        mvc.perform(post("/token").contentType(MediaType.TEXT_PLAIN).content("alice"))
                .andExpect(status().isUnsupportedMediaType());
    }

    @Test
    void exposesHealth() throws Exception {
        mvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }
}
