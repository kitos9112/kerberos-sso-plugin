# Design: recognising Kerberos machine principals

**Status:** draft, for review. No implementation exists.
**Author:** kitos9112 · **Date:** 2026-09-01

## Summary

Let domain-joined hosts authenticate to Jenkins with the Kerberos credentials they already have
(`host/fqdn@REALM` on Unix, `NAME$@REALM` for a Windows computer account), instead of distributing
long-lived Jenkins API tokens to every machine that needs to call the API.

This is deliberately *not* a protocol change. SPNEGO already accepts these principals — the KDC
vouches for them and the plugin's authenticator validates them today. The gap is entirely in what
happens **after** validation.

## Problem

`KerberosSSOFilter` assumes every validated principal is a user. It strips the realm and calls
`SecurityRealm.loadUserByUsername2` (lines 204–226). A machine principal is not a user in the
security realm, so the lookup fails, the request is logged as
`Username {0} not registered by Jenkins`, and it proceeds **anonymous**.

So a domain-joined host doing `kinit -k` and curling Jenkins authenticates successfully at the
Kerberos layer and then silently gets nothing.

## Scope

**In scope:** keytab-backed API automation. Scripts and services on domain-joined hosts calling the
Jenkins API as themselves.

**Explicitly out of scope:**

- The inbound agent connection problem. Different client, no SPNEGO on that path, and JNLP secrets
  already authenticate agents. Solved separately by JENKINS-75881 / `bypassPaths`.
- Gating Jenkins to domain-joined machines only. That is a perimeter concern, better served by mTLS
  at the reverse proxy.
- Any change to `jenkinsci/remoting`.

## Decisions taken

| Question | Decision | Rationale |
|---|---|---|
| Credential model | Machines' own host keytabs / computer accounts | Zero distribution, zero rotation. Dedicated `svc-*` accounts already work with no code change — that is a documentation topic, not a feature. |
| Mapping model | Allowlist → virtual machine users | Deny by default, per-machine identity for audit, no default group membership. |
| Architecture | One branch in the filter + config; detection/mapping in a package-private class | Smallest reviewable change. An `ExtensionPoint` (see Alternatives) becomes an extraction later rather than a rewrite. |

## Non-negotiable security property

**Machine principals must never resolve through the general user lookup.** Active Directory contains
computer objects; a realm that happens to resolve `AGENT01$` would silently grant every domain
workstation whatever authenticated users can do. Machine credentials are also the easiest credentials
in a domain to obtain — any local administrator on any domain-joined workstation holds that machine's
ticket. The machine path is therefore a separate, deny-by-default code path.

## Design

### 1. Control flow

A new decision point in `KerberosSSOFilter.doFilter`, after SPNEGO validation and before the realm
lookup:

- principal is machine-shaped **and** matches the allowlist → construct authentication directly
- principal is machine-shaped **and** does not match → log at WARNING, proceed anonymous
  (identical to today's unknown-user behaviour)
- otherwise → existing user path, untouched

With the feature unconfigured (empty allowlist) behaviour is byte-identical to today.

### 2. Recognition and matching

- Machine-shaped: realm-stripped name contains `/` or ends with `$`.
- Allowlist entries are simple `*` globs, **not** regex — no ReDoS surface, less to review.
- Matched case-insensitively against the **full principal including realm**
  (`host/*.example.com@EXAMPLE.COM`, `*$@EXAMPLE.COM`). Realm-inclusive matching is a security
  decision: in a multi-realm forest a foreign realm's `host/agent01` must not satisfy a realm-less
  pattern.
- Resulting Jenkins username: realm-stripped principal, lowercased (`host/agent01.example.com`,
  `agent01$`). Lowercased because Windows presents `AGENT01$` and matrix-auth SIDs need stability.

Known limitations, documented rather than solved in v1:

- Identical machine names in different realms collide on username.
- One physical machine presenting both shapes is two distinct identities.

### 3. Identity construction

On match, an authentication token carrying the machine username and exactly one authority: the group
`kerberos-machines`.

Deliberately **not** done: no Jenkins `User` record is created, no user-seed population, no
`SecurityListener.fireLoggedIn`. Those are user-lifecycle semantics, and a fleet of machines should
not mint thousands of user records. Auditing is an INFO log line per authentication.

Permissions come solely from explicit matrix-auth grants to the `kerberos-machines` SID or to
individual machine names. Out of the box, a matched machine can do nothing.

### 4. Configuration

`machinePrincipalPatterns` on `PluginImpl`: textarea, one pattern per line, JCasC list binding, empty
by default. This mirrors the `bypassPaths` machinery already shipped and reviewed — `ADMINISTER` on
the setter, `SYSTEM_READ` on the string getter, package-private raw getter for the filter. Malformed
patterns rejected at configuration time.

### 5. Risks

**R1 — "no default groups" is unverified and load-bearing.** Whether matrix-auth's `authenticated`
SID matches any non-anonymous authentication regardless of authorities has not been tested. The
entire trust model rests on it. **The first implementation task is a spike**: grant `authenticated`
a permission, assert a machine token does not hold it. If that cannot be enforced, stop and redesign
— the rest of this document is void.

**R2 — deployment mode affects usability.** Under `anonymousAccess: false` (the mode our controller
now runs) every request is challenged, so keytab-backed automation gets transparent per-request
SPNEGO with no extra work. Under `anonymousAccess: true` the filter only negotiates at `/login`, so
callers must authenticate there first and replay the session cookie. Worth documenting; not a
blocker.

**R3 — credential strength.** A machine credential is weaker than a user credential in practice.
This is mitigated by deny-by-default and zero default permissions, not eliminated. Operators should
grant machine identities the minimum required, and the documentation should say so plainly.

## Alternatives considered

- **`MachinePrincipalResolver` extension point.** The "right" architecture if multiple mapping
  strategies are ever needed. Premature with exactly one known consumer; the package-private class
  keeps the extraction cheap.
- **All machines → one shared service user.** Trivial to reason about, one grant to manage, but no
  per-machine audit trail and a compromised laptop becomes indistinguishable from a deploy host.
- **Explicit principal→user table.** Maximum control and per-machine revocation, but reintroduces
  per-host provisioning, which erodes the zero-distribution advantage that motivated host keytabs.
- **Rewrite principal and delegate to the security realm.** Least code, but delegates trust to
  whatever LDAP returns — the silent-escalation path ruled out above.

## Testing

- Mock authenticator returning `host/…` and `NAME$` principals.
- The R1 spike retained as a permanent regression test, asserting no `authenticated`-group leakage.
- Pattern matching: realm mismatch, case-insensitivity, glob edges.
- JCasC and configuration form round-trips.
- A test pinning that an empty allowlist makes the machine path unreachable.

Note the existing suite mocks `KerberosAuthenticator` throughout, so none of it exercises real
`org.codelibs.spnego` code. That limitation applies here too.

## Review notes

Specific feedback wanted on:

1. Is R1 the right thing to block on, and is there a known answer already?
2. Is realm-inclusive matching right, or surprising to operators?
3. Should `host/agent01.example.com` and `AGENT01$` be unified as one identity in v1?
4. Is `kerberos-machines` as a single group too coarse?
