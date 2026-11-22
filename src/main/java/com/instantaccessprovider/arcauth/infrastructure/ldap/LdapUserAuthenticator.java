// SPDX-FileCopyrightText: 2026 Dédale Solutions
// SPDX-License-Identifier: EUPL-1.2
package com.instantaccessprovider.arcauth.infrastructure.ldap;

import com.instantaccessprovider.arcauth.domain.exception.AuthenticationUnavailableException;
import com.instantaccessprovider.arcauth.domain.model.AuthenticatedUser;
import com.instantaccessprovider.arcauth.domain.port.UserAuthenticatorPort;
import org.springframework.ldap.AuthenticationException;
import org.springframework.ldap.NamingException;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.AbstractContextMapper;
import org.springframework.ldap.core.support.AbstractContextSource;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.ldap.query.SearchScope;
import org.springframework.ldap.support.LdapUtils;

import javax.naming.directory.DirContext;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Authentification par bind : un compte de service recherche l'utilisateur, puis le mot
 * de passe est vérifié en ouvrant une connexion avec le DN de l'utilisateur. Le mot de
 * passe n'est jamais lu ni comparé par le service. Les groupes sont ensuite recherchés
 * ({@code groupOfNames}, attribut {@code member}).
 */
public class LdapUserAuthenticator implements UserAuthenticatorPort {

    private final AbstractContextSource contextSource;
    private final LdapTemplate ldapTemplate;
    private final String userSearchBase;
    private final String userSearchFilter;
    private final String groupSearchBase;

    /**
     * @param contextSource    connexion du compte de service (lecture seule)
     * @param userSearchBase   base de recherche des utilisateurs
     * @param userSearchFilter filtre de recherche, {@code {0}} étant l'identifiant saisi (échappé)
     * @param groupSearchBase  base de recherche des groupes
     */
    public LdapUserAuthenticator(AbstractContextSource contextSource,
                                 String userSearchBase,
                                 String userSearchFilter,
                                 String groupSearchBase) {
        this.contextSource = contextSource;
        this.ldapTemplate = new LdapTemplate(contextSource);
        this.userSearchBase = userSearchBase;
        this.userSearchFilter = userSearchFilter;
        this.groupSearchBase = groupSearchBase;
    }

    @Override
    public Optional<AuthenticatedUser> authenticate(String username, String password) {
        try {
            List<UserEntry> candidates = ldapTemplate.search(
                    LdapQueryBuilder.query()
                            .base(userSearchBase)
                            .searchScope(SearchScope.SUBTREE)
                            .countLimit(2)
                            .filter(userSearchFilter, username),
                    new AbstractContextMapper<UserEntry>() {
                        @Override
                        protected UserEntry doMapFromContext(DirContextOperations ctx) {
                            return new UserEntry(
                                    ctx.getNameInNamespace(),
                                    ctx.getStringAttribute("uid"),
                                    ctx.getStringAttribute("cn"));
                        }
                    });

            // Un identifiant ambigu est refusé plutôt que départagé arbitrairement.
            if (candidates.size() != 1) {
                return Optional.empty();
            }
            UserEntry entry = candidates.get(0);

            if (!passwordMatches(entry.dn(), password)) {
                return Optional.empty();
            }

            String subject = entry.uid() != null && !entry.uid().isBlank() ? entry.uid() : username;
            return Optional.of(new AuthenticatedUser(subject, entry.commonName(), groupsOf(entry.dn())));
        } catch (NamingException e) {
            throw new AuthenticationUnavailableException("Annuaire indisponible", e);
        }
    }

    private boolean passwordMatches(String userDn, String password) {
        DirContext context = null;
        try {
            context = contextSource.getContext(userDn, password);
            return true;
        } catch (AuthenticationException e) {
            return false;
        } finally {
            LdapUtils.closeContext(context);
        }
    }

    private Set<String> groupsOf(String userDn) {
        List<String> names = ldapTemplate.search(
                LdapQueryBuilder.query()
                        .base(groupSearchBase)
                        .searchScope(SearchScope.SUBTREE)
                        .filter("(&(objectClass=groupOfNames)(member={0}))", userDn),
                new AbstractContextMapper<String>() {
                    @Override
                    protected String doMapFromContext(DirContextOperations ctx) {
                        return ctx.getStringAttribute("cn");
                    }
                });
        Set<String> groups = new HashSet<>();
        for (String name : names) {
            if (name != null && !name.isBlank()) {
                groups.add(name);
            }
        }
        return groups;
    }

    private record UserEntry(String dn, String uid, String commonName) {
    }
}
