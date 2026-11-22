// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.domain.service;

import com.instantaccessprovider.arcauth.domain.model.Role;

import java.util.Collection;
import java.util.EnumMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Déduit les rôles ARC à partir des groupes de l'annuaire. Les noms de groupes sont
 * comparés sans tenir compte de la casse.
 */
public class RoleMapper {

    private final Map<Role, String> groupByRole = new EnumMap<>(Role.class);

    public RoleMapper(String adminGroup, String publisherGroup, String readerGroup) {
        groupByRole.put(Role.ARC_ADMIN, normalize(adminGroup));
        groupByRole.put(Role.ARC_PUBLISHER, normalize(publisherGroup));
        groupByRole.put(Role.ARC_READER, normalize(readerGroup));
    }

    /**
     * @return les rôles correspondant aux groupes, dans l'ordre de déclaration de {@link Role}
     */
    public List<Role> rolesFor(Collection<String> groups) {
        if (groups == null || groups.isEmpty()) {
            return List.of();
        }
        List<String> normalized = groups.stream().map(RoleMapper::normalize).toList();
        return groupByRole.entrySet().stream()
                .filter(e -> !e.getValue().isEmpty() && normalized.contains(e.getValue()))
                .map(Map.Entry::getKey)
                .toList();
    }

    private static String normalize(String group) {
        return group == null ? "" : group.trim().toLowerCase(Locale.ROOT);
    }
}
