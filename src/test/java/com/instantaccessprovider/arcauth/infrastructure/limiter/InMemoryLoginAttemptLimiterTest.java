// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.infrastructure.limiter;

import com.instantaccessprovider.arcauth.domain.model.AttemptKey;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryLoginAttemptLimiterTest {

    private final MutableClock clock = new MutableClock(Instant.parse("2026-01-01T10:00:00Z"));
    private final InMemoryLoginAttemptLimiter limiter =
            new InMemoryLoginAttemptLimiter(4, 2, Duration.ofMinutes(5), clock);

    @Test
    void blocksIdentifierAtItsThreshold() {
        AttemptKey alice = AttemptKey.ofIdentifier("alice");

        limiter.recordFailure(alice);
        assertThat(limiter.isBlocked(alice)).isFalse();
        limiter.recordFailure(alice);
        assertThat(limiter.isBlocked(alice)).isTrue();
    }

    @Test
    void addressHasItsOwnThreshold() {
        AttemptKey address = AttemptKey.ofAddress("10.0.0.1");

        for (int i = 0; i < 3; i++) {
            limiter.recordFailure(address);
        }
        assertThat(limiter.isBlocked(address)).isFalse();
        limiter.recordFailure(address);
        assertThat(limiter.isBlocked(address)).isTrue();
    }

    @Test
    void identifiersAreCaseInsensitiveAndIndependent() {
        limiter.recordFailure(AttemptKey.ofIdentifier("Alice"));
        limiter.recordFailure(AttemptKey.ofIdentifier("ALICE"));

        assertThat(limiter.isBlocked(AttemptKey.ofIdentifier("alice"))).isTrue();
        assertThat(limiter.isBlocked(AttemptKey.ofIdentifier("bob"))).isFalse();
    }

    @Test
    void failuresExpireWithTheWindow() {
        AttemptKey alice = AttemptKey.ofIdentifier("alice");
        limiter.recordFailure(alice);
        limiter.recordFailure(alice);
        assertThat(limiter.isBlocked(alice)).isTrue();

        clock.advance(Duration.ofMinutes(5));

        assertThat(limiter.isBlocked(alice)).isFalse();
    }

    @Test
    void resetClearsFailures() {
        AttemptKey alice = AttemptKey.ofIdentifier("alice");
        limiter.recordFailure(alice);
        limiter.recordFailure(alice);

        limiter.reset(alice);

        assertThat(limiter.isBlocked(alice)).isFalse();
    }

    private static final class MutableClock extends Clock {

        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
