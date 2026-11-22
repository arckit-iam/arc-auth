// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.domain.service;

import com.instantaccessprovider.arcauth.domain.model.Role;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RoleMapperTest {

    private final RoleMapper mapper = new RoleMapper("arc-admins", "arc-publishers", "arc-readers");

    @Test
    void mapsEachGroupToItsRole() {
        assertThat(mapper.rolesFor(Set.of("arc-publishers"))).containsExactly(Role.ARC_PUBLISHER);
        assertThat(mapper.rolesFor(Set.of("arc-readers"))).containsExactly(Role.ARC_READER);
        assertThat(mapper.rolesFor(Set.of("arc-admins"))).containsExactly(Role.ARC_ADMIN);
    }

    @Test
    void combinesRolesInEnumOrder() {
        assertThat(mapper.rolesFor(List.of("arc-readers", "arc-admins")))
                .containsExactly(Role.ARC_ADMIN, Role.ARC_READER);
    }

    @Test
    void ignoresCaseAndUnknownGroups() {
        assertThat(mapper.rolesFor(Set.of("ARC-Admins", "finance"))).containsExactly(Role.ARC_ADMIN);
    }

    @Test
    void returnsNothingWithoutMatchingGroup() {
        assertThat(mapper.rolesFor(Set.of("finance"))).isEmpty();
        assertThat(mapper.rolesFor(Set.of())).isEmpty();
        assertThat(mapper.rolesFor(null)).isEmpty();
    }

    @Test
    void blankGroupNameNeverMatches() {
        RoleMapper unconfigured = new RoleMapper("arc-admins", "", null);
        assertThat(unconfigured.rolesFor(Set.of(""))).isEmpty();
    }
}
