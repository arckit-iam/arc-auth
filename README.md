# arc-auth

Service d'authentification de la plateforme InstantAccessProvider : vérifie l'identité d'un utilisateur dans un annuaire LDAP (bind) et émet un jeton d'accès JWT signé, que les services ARC valident.

> **Statut : version 0.1, validée sur Apache DS.** Émission de jetons et publication des clés (JWKS). `arc-publisher` et `product-manager` valident ces jetons ; voir [arc-docs, document 13](https://github.com/arckit-iam/arc-docs/blob/main/docs/13-authentification-jwt.md).

## But

- Authentifier un utilisateur ou un compte de service par un bind LDAP : le service ne lit ni ne compare jamais le mot de passe.
- Déduire les rôles ARC (`ARC_ADMIN`, `ARC_PUBLISHER`, `ARC_READER`) des groupes de l'annuaire (`groupOfNames`).
- Émettre un jeton JWT court (15 minutes par défaut), signé en RS256.
- Publier les clés publiques de vérification (JWKS).

Le service est sans état : aucune base de données ni session. Verrouillage de compte, politique de mot de passe et expiration relèvent de l'annuaire.

## API

| Méthode | Chemin | Rôle |
|---|---|---|
| `POST` | `/token` | Corps `{"username":"…","password":"…"}` ; réponse `{"access_token":"…","token_type":"Bearer","expires_in":900}` |
| `GET` | `/.well-known/jwks.json` | Clés publiques actives |
| `GET` | `/actuator/health` | Santé du service |

Réponses d'erreur de `/token` :

| Code | Cas |
|---|---|
| `401` | Identifiants refusés, ou utilisateur sans aucun rôle ARC. Réponse identique pour un identifiant inconnu et un mot de passe erroné. |
| `429` | Trop d'échecs successifs pour l'adresse source ou l'identifiant |
| `503` | Annuaire injoignable |

Exemple :

```bash
curl -s -X POST http://localhost:8082/token \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"…"}'
```

### Contenu du jeton

| Claim | Valeur |
|---|---|
| `iss` | `ARC_AUTH_JWT_ISSUER` |
| `sub` | identifiant (`uid`) |
| `aud` | `ARC_AUTH_JWT_AUDIENCE` |
| `iat`, `nbf`, `exp` | émission, début de validité, expiration |
| `jti` | identifiant unique du jeton |
| `name` | nom complet (`cn`) |
| `roles` | rôles ARC |

L'en-tête porte `alg: RS256` et un `kid` correspondant à une clé du JWKS.

## Rôles

| Groupe de l'annuaire (par défaut) | Rôle |
|---|---|
| `arc-admins` | `ARC_ADMIN` |
| `arc-publishers` | `ARC_PUBLISHER` |
| `arc-readers` | `ARC_READER` |

Un utilisateur membre d'aucun de ces groupes ne reçoit pas de jeton.

## Configuration

| Variable | Rôle | Défaut |
|---|---|---|
| `SERVER_PORT` | Port HTTP | `8082` |
| `ARC_AUTH_LDAP_URL` | Annuaire (`ldaps://` hors démonstration) | `ldap://localhost:10389` |
| `ARC_AUTH_LDAP_MANAGER_DN` / `ARC_AUTH_LDAP_MANAGER_PASSWORD` | Compte de service en lecture seule (vide : accès anonyme) | vide |
| `ARC_AUTH_LDAP_USER_SEARCH_BASE` | Base de recherche des utilisateurs | `ou=Users,dc=example,dc=com` |
| `ARC_AUTH_LDAP_USER_SEARCH_FILTER` | Filtre ; `{0}` est l'identifiant saisi, échappé | `(uid={0})` |
| `ARC_AUTH_LDAP_GROUP_SEARCH_BASE` | Base de recherche des groupes | `ou=Groups,dc=example,dc=com` |
| `ARC_AUTH_JWT_ISSUER` | Valeur de `iss` (**obligatoire**) | aucun |
| `ARC_AUTH_JWT_AUDIENCE` | Valeur de `aud` | `arc` |
| `ARC_AUTH_JWT_TTL` | Durée de vie du jeton (ISO 8601) | `PT15M` |
| `ARC_AUTH_JWT_PRIVATE_KEY_PATH` | Clé privée RSA, PEM PKCS#8, 2048 bits minimum | clé éphémère (démonstration seulement) |
| `ARC_AUTH_JWT_KEY_ID` | `kid` | empreinte SHA-256 de la clé publique |
| `ARC_AUTH_JWT_ADDITIONAL_PUBLIC_KEY_PATHS` | Clés publiques PEM supplémentaires, séparées par des virgules (rotation) | vide |
| `ARC_AUTH_ROLE_ADMIN_GROUP` / `_PUBLISHER_GROUP` / `_READER_GROUP` | Groupes associés aux rôles | `arc-admins` / `arc-publishers` / `arc-readers` |
| `ARC_AUTH_RATE_LIMIT_MAX_FAILURES_PER_ADDRESS` | Échecs tolérés par adresse source | `20` |
| `ARC_AUTH_RATE_LIMIT_MAX_FAILURES_PER_IDENTIFIER` | Échecs tolérés par identifiant | `5` |
| `ARC_AUTH_RATE_LIMIT_WINDOW` | Fenêtre de comptage des échecs | `PT5M` |

Fournir le mot de passe du compte de service et la clé privée par secret d'exécution, jamais dans l'image ni dans le dépôt.

### Clé de signature

Générer la paire hors du service :

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out arc-auth-private.pem
openssl pkey -in arc-auth-private.pem -pubout -out arc-auth-public.pem
```

Sans `ARC_AUTH_JWT_PRIVATE_KEY_PATH`, une clé éphémère est générée au démarrage et un avertissement est journalisé : les jetons ne survivent pas à un redémarrage. À réserver à la démonstration.

Rotation : ajouter la nouvelle paire en clé de signature, conserver l'ancienne clé publique dans `ARC_AUTH_JWT_ADDITIONAL_PUBLIC_KEY_PATHS` jusqu'à l'expiration du dernier jeton qu'elle a signé, puis la retirer.

### Sécurité

- Déployer derrière TLS : les mots de passe transitent dans le corps de `POST /token`, et le lien avec l'annuaire doit utiliser `ldaps://`.
- La limitation de débit est tenue en mémoire par instance et se fonde sur l'adresse de la connexion TCP. Derrière un proxy, configurer la transmission de l'adresse d'origine (`server.forward-headers-strategy`) uniquement si le proxy est de confiance.
- Pas de jeton de rafraîchissement ni de liste de révocation : la révocation passe par la durée de vie courte et la rotation de clé.

## Lancement local

```bash
ARC_AUTH_JWT_ISSUER=http://localhost:8082 mvn spring-boot:run
```

## Build et tests

```bash
mvn clean package
```

Les tests d'intégration démarrent un annuaire **Apache DS embarqué** (partition en mémoire, port éphémère) : aucun serveur à installer. Apache DS n'est utilisé que pour les tests et n'est pas livré dans l'image.

## Documentation

La documentation d'architecture de la plateforme est dans le dépôt [arc-docs](https://github.com/arckit-iam/arc-docs) :

- [Architecture globale](https://github.com/arckit-iam/arc-docs/blob/main/docs/02-architecture-globale.md).
- [Authentification et autorisation par jeton JWT](https://github.com/arckit-iam/arc-docs/blob/main/docs/13-authentification-jwt.md).

Le déploiement GitOps (Helm, FluxCD) est géré dans un dépôt privé. L'intégration et la mise en production de la plateforme sont proposées par Dédale Solutions en **service payant** : pour en discuter, contactez-nous à [etiennsalle@gmail.com](mailto:etiennsalle@gmail.com).

## Licence

Copyright © 2026 Dédale Solutions

Ce projet est distribué sous la licence [EUPL-1.2](LICENSE) (European Union Public Licence v. 1.2).
