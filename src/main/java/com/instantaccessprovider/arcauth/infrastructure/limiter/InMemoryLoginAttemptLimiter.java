// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.infrastructure.limiter;

import com.instantaccessprovider.arcauth.domain.model.AttemptKey;
import com.instantaccessprovider.arcauth.domain.port.LoginAttemptLimiterPort;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Limiteur en mémoire à fenêtre glissante. Chaque instance du service compte ses propres
 * échecs : avec plusieurs réplicas, le seuil effectif est multiplié par leur nombre.
 * Le nombre de clés suivies est borné pour qu'un flot d'identifiants aléatoires ne
 * puisse pas saturer la mémoire.
 */
public class InMemoryLoginAttemptLimiter implements LoginAttemptLimiterPort {

    private static final int MAX_TRACKED_KEYS = 10_000;

    private final int maxFailuresPerAddress;
    private final int maxFailuresPerIdentifier;
    private final Duration window;
    private final Clock clock;
    private final Map<AttemptKey, Deque<Instant>> failures = new HashMap<>();

    public InMemoryLoginAttemptLimiter(int maxFailuresPerAddress,
                                       int maxFailuresPerIdentifier,
                                       Duration window,
                                       Clock clock) {
        this.maxFailuresPerAddress = maxFailuresPerAddress;
        this.maxFailuresPerIdentifier = maxFailuresPerIdentifier;
        this.window = window;
        this.clock = clock;
    }

    @Override
    public synchronized boolean isBlocked(AttemptKey key) {
        Deque<Instant> attempts = failures.get(key);
        if (attempts == null) {
            return false;
        }
        evictExpired(attempts);
        if (attempts.isEmpty()) {
            failures.remove(key);
            return false;
        }
        return attempts.size() >= threshold(key);
    }

    @Override
    public synchronized void recordFailure(AttemptKey key) {
        if (!failures.containsKey(key) && failures.size() >= MAX_TRACKED_KEYS) {
            purgeExpired();
            if (failures.size() >= MAX_TRACKED_KEYS) {
                return;
            }
        }
        Deque<Instant> attempts = failures.computeIfAbsent(key, k -> new ArrayDeque<>());
        evictExpired(attempts);
        attempts.addLast(clock.instant());
    }

    @Override
    public synchronized void reset(AttemptKey key) {
        failures.remove(key);
    }

    private int threshold(AttemptKey key) {
        return key.type() == AttemptKey.Type.SOURCE_ADDRESS ? maxFailuresPerAddress : maxFailuresPerIdentifier;
    }

    private void evictExpired(Deque<Instant> attempts) {
        Instant limit = clock.instant().minus(window);
        while (!attempts.isEmpty() && !attempts.peekFirst().isAfter(limit)) {
            attempts.removeFirst();
        }
    }

    private void purgeExpired() {
        Iterator<Map.Entry<AttemptKey, Deque<Instant>>> it = failures.entrySet().iterator();
        while (it.hasNext()) {
            Deque<Instant> attempts = it.next().getValue();
            evictExpired(attempts);
            if (attempts.isEmpty()) {
                it.remove();
            }
        }
    }
}
