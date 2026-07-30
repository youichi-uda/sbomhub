# Outbound egress policy

How SBOMHub decides where it is allowed to make an outbound HTTP request, and
what that decision does and does not protect you from.

Introduced in M50. Operator-facing migration steps are in
[UPGRADE.md §2c](../UPGRADE.md); this document is the design and the honest
limits.

---

## 1. The problem

Several settings screens accept a URL from a **tenant administrator** and the
server then connects to it. That is a server-side request forgery surface: the
person choosing the destination is not the person who owns the network the
server sits on.

The four tenant-controlled destinations:

| Purpose | Stored in | Dialed by |
|---|---|---|
| `issue_tracker` | `issue_tracker_connections.base_url` | `internal/client/{jira,backlog,github_issues}.go` |
| `notification_webhook` | `notification_settings.slack_webhook_url` / `.discord_webhook_url` | `internal/service/notification.go` |
| `diff_webhook` | `tenant_diff_webhook_settings.webhook_url` | `internal/service/diff_webhook/` |
| `tenant_llm` | `tenant_llm_config.azure_endpoint` | `internal/service/llm/azure_openai.go` |

Everything else SBOMHub connects to is chosen by the **operator** — the
vulnerability feed mirrors (`SBOMHUB_NVD_URL` and friends), the Ollama base URL
(`SBOMHUB_LLM_OLLAMA_URL` / `OLLAMA_HOST`), the billing provider API. Those are
deliberately **not** filtered. The operator already controls the process;
filtering their own configuration against their own policy buys no security, and
doing it would break the documented local-LLM deployment, whose default base URL
is `http://localhost:11434`.

---

## 2. Where the decision is made, and why it is there

The intuitive design is: parse the URL, resolve the hostname, refuse if any
answer is internal, then hand the URL to an ordinary HTTP client.

That does not work. The client resolves the name **again** when it connects. An
attacker who controls the authoritative DNS for a name they own can answer with
a routable address for the validation lookup and `127.0.0.1` for the connect
lookup. The check and the connection are two different facts about the world,
and only the second one matters.

So the enforcement point is the **dialer** (`internal/egress/guard.go`):

- `Guard.DialContext` resolves the name itself, classifies every answer, drops
  the ones the policy refuses, and then connects to one of the addresses it just
  accepted — as a literal, so there is no second resolution.
- `net.Dialer.Control` re-checks the concrete address immediately before the
  socket connects. With the loop above dialing literals this is the same verdict
  twice, which is the intent: "the address checked is the address connected"
  holds structurally, not by reading the code carefully.

The rules an address cannot express — the scheme, the hostname allowlist — are
enforced one layer up, by a `RoundTripper` that runs on **every** request. That
placement matters: `CheckRedirect` fires only when a redirect is being followed,
so without the round tripper those rules would apply to the initial request only
if the caller happened to have called `ValidateURL` first, making the guarantee a
property of each call site rather than of the client.

Redirects are the same problem in different clothing. A destination that passes
every check can answer `302` with a `Location` pointing anywhere. Two things
cover that:

- The redirect hop reuses the same `Transport`, so it goes through the same
  guarded dialer. A redirect to an internal address is refused at connect time
  whether or not anything inspected the `Location` header.
- `Guard.CheckRedirect` re-applies the URL-level rules (scheme, hostname
  allowlist) that the dialer cannot see, and caps the hop count.

`Guard.ValidateURL` exposes the same URL-level check for the settings handlers to
call at save time. **Its presence at a call site is not what makes the deployment
safe.** It is there so an administrator who types `http://127.0.0.1:8080` gets an
immediate 400 with a readable reason instead of a webhook that silently never
fires. A hostname that merely *resolves* internally passes it, by design — that
case is not knowable at save time, and is caught at connect time instead.

`Guard.Client()` is the entry point that enforces the whole policy.
`Guard.Transport()` enforces the address rules only, and is exported for
connection-pool access and tests; installing it directly gives a
partially-enforcing client.

---

## 3. The two tiers

`internal/egress/ip.go` classifies every destination address into one of three
classes.

### `ClassBlocked` — refused by every policy, no setting re-enables it

| Range | Why |
|---|---|
| `169.254.0.0/16`, `fe80::/10` | Link-local. Carries the AWS / GCP / Azure / Alibaba instance metadata service at `169.254.169.254`. |
| `168.63.129.16/32` | Azure platform host agent ("wireserver"). Routable-looking, answers only from inside an Azure VM. |
| `100.100.100.200/32` | Alibaba Cloud instance metadata. Sits *inside* CGNAT, which is otherwise `ClassPrivate`. |
| `fd00:ec2::254/128` | AWS IMDS over IPv6. Sits *inside* `fc00::/7`, which is otherwise `ClassPrivate`. |
| `fd20:ce::254/128` | Google Cloud metadata over IPv6. Also inside `fc00::/7`. |
| `0.0.0.0/8`, `::/128` | Unspecified / this-network. Resolves to the local host on most stacks. |
| `224.0.0.0/4`, `ff00::/8` | Multicast. |
| `240.0.0.0/4` | Reserved, includes the `255.255.255.255` broadcast address. |
| `192.0.0.0/24` | IETF protocol assignments, includes the NAT64 discovery address. |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | TEST-NET documentation ranges. |
| `198.18.0.0/15` | Benchmarking range. |
| `100::/64` | IPv6 discard-only prefix. |
| `2001::/23` | IETF Protocol Assignments, as a whole block. Contains Teredo (`2001::/32`, which encapsulates an arbitrary IPv4 destination), IPv6 benchmarking, AMT, AS112-v6 and several anycast addresses — a mix of globally routable and not, whose membership changes as IANA allocates. RIR-allocated global unicast starts at `2001:200::/23`, clear of this. |
| `2001:db8::/32`, `3fff::/20` | IPv6 documentation ranges. |
| `5f00::/16` | Locally scoped SRv6 SIDs. |
| `fec0::/10` | Deprecated IPv6 site-local. |
| `100:0:0:1::/64` | Dummy prefix. |
| `192.88.99.0/24` | 6to4 relay anycast (deprecated). |
| `64:ff9b:1::/48` | Local-use IPv4/IPv6 translation prefix. Unlike the well-known `/96` it is technology-agnostic, so the embedded IPv4 address has no fixed offset and cannot be decoded and judged — blocked outright. |

Addresses that **embed** an IPv4 address are decoded and judged by what they
embed, not treated as opaque: NAT64 (`64:ff9b::/96`), 6to4 (`2002::/16`) and the
deprecated IPv4-compatible form (`::a.b.c.d`). So `64:ff9b::a9fe:a9fe` is
refused — it is the metadata address wearing a costume — while
`64:ff9b::808:808` (8.8.8.8) is not. This matters: without it, a NAT64-capable
network turns every IPv4 rule above into a no-op.

RFC 6052 also allows a network to use **its own** translation prefix, at any of
`/32`, `/40`, `/48`, `/56`, `/64` or `/96`. Those cannot be recognised by
inspection, so an operator on such a network must declare them:

```bash
SBOMHUB_EGRESS_NAT64_PREFIXES=fd00:1234::/32
```

Without the declaration, an address under a custom NAT64 prefix looks like
ordinary public IPv6 and every IPv4 rule above is bypassed for translated
traffic.

A declaration is checked at startup and is refused when it:

- is not one of the six RFC 6052 lengths;
- is a `/96` whose octet at bits 64–71 is non-zero (RFC 6052 requires it to be
  zero, and for a `/96` that octet is inside the prefix);
- overlaps a built-in translation format (`64:ff9b::/96`, `2002::/16`, `::/96`),
  which are always decoded — the declaration would do nothing; or
- sits inside a permanently blocked range. **A declaration can never re-open a
  `ClassBlocked` address**: the blocked tables are consulted before any declared
  prefix, so even a declaration forced through in code cannot decode
  `64:ff9b:1:…` or `fe80::…` into something permitted.

An address under a declared prefix whose u-octet (bits 64–71) is non-zero is not
a valid RFC 6052 translated address, and is classified by the ordinary tables
instead of being decoded — so a native host inside a declared ULA prefix keeps
its private classification.

CIDR exemptions are tested against **both** the outer IPv6 address and the
embedded IPv4 address, so `SBOMHUB_EGRESS_ALLOWED_INTERNAL=192.168.0.0/16` works
on a NAT64 network even though the address dialed is IPv6.

IPv4-mapped IPv6 (`::ffff:a.b.c.d`) is normalised before any of this, so
`::ffff:169.254.169.254` and `169.254.169.254` are the same address to the
classifier.

### `ClassBlocked` — IPv6 outside the delegated global-unicast range

IPv6 outside `2000::/3` is not delegated for global unicast at all, so an address
there is either reserved by the IETF or locally invented. Every legitimate
non-global form that lives outside `2000::/3` — ULA, link-local, multicast,
loopback, the well-known NAT64 prefix — is classified by the rules above before
this one is reached.

**Known gap:** unallocated space *inside* `2000::/3` (`3000::/5` and similar)
still classifies as public. Enumerating IANA's allocations within `2000::/3`
would need re-checking against the registry on every release, and a stale
allowlist is a worse failure than this gap.

### `ClassPrivate` — gated on operator opt-in

`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`,
`100.64.0.0/10` (carrier-grade NAT), `::1/128`, `fc00::/7` (IPv6 unique-local),
plus the name `localhost` and anything under `.localhost` (RFC 6761 reserves
those for the loopback interface, so they can be judged without resolving).

Refused by default in **every** deployment mode, self-hosted included: a URL a
tenant typed is untrusted input wherever it was typed.

---

## 4. Configuration

```bash
# Blunt: open every internal address for all four tenant-configured purposes.
SBOMHUB_EGRESS_ALLOW_PRIVATE=false   # default

# Narrow, and preferred: open only these. Hostnames, bare IPs, CIDRs;
# comma- or space-separated. A hostname entry also matches its subdomains.
SBOMHUB_EGRESS_ALLOWED_INTERNAL=jira.corp.example,10.20.0.0/24

# Honour HTTP_PROXY / HTTPS_PROXY for these four purposes. Default false —
# see §5.1, this genuinely gives up the dial-time guarantee.
SBOMHUB_EGRESS_ALLOW_PROXY=false     # default

# Declare this network's RFC 6052 NAT64 translation prefixes, so addresses
# reached through them are judged by the IPv4 address they embed. Only needed
# when the prefix is not the well-known 64:ff9b::/96.
SBOMHUB_EGRESS_NAT64_PREFIXES=
```

A malformed `SBOMHUB_EGRESS_ALLOWED_INTERNAL` entry is a **startup refusal**, not
a skipped one. An operator who mistypes an exemption otherwise believes they have
opened a path that is in fact still closed, and the usual next move after that
confusion is to set `ALLOW_PRIVATE=true` and open everything.

Neither setting affects `ClassBlocked`.

### Per-purpose differences

| Purpose | Plaintext `http://` | Redirects | Hostname allowlist |
|---|---|---|---|
| `issue_tracker` | refused | up to 3, re-checked per hop | SaaS mode only: `atlassian.net`, `jira.com`, `backlog.com`, `backlog.jp`, `github.com`, `api.github.com` |
| `notification_webhook` | permitted | up to 3, re-checked per hop | none |
| `diff_webhook` | permitted | **not followed** — a 3xx is returned as an ordinary response | none |
| `tenant_llm` | permitted | up to 3, re-checked per hop | none |

Each difference is inherited, not invented: the issue tracker required https
before M50 because the connection carries an API token; the diff webhook refused
redirects before M50 because a 307 preserves method and body and could carry an
unsigned payload off the host the signing exemption was evaluated against.

---

## 5. What this does not protect you from

Stated plainly, because a guard whose limits are undocumented gets trusted for
things it does not do.

1. **An HTTP proxy, if you turn one on.** `HTTP_PROXY` / `HTTPS_PROXY` are
   ignored by default for these four purposes, precisely because a proxy defeats
   the mechanism: Go hands the dialer the *proxy's* address, and the proxy — not
   this code — resolves and reaches the final destination. The guard would
   approve the proxy while a refused destination is reached over the connection
   it approved.

   `SBOMHUB_EGRESS_ALLOW_PROXY=true` restores proxy support and is logged at
   WARN on startup. It is a deliberate delegation: with it set, the destination
   policy must be enforced on the proxy, and nothing in this package can
   substitute for that.

   The cost of the default is real: a deployment whose only route out is a proxy
   will find these four integrations unable to reach anything until the flag is
   set.

2. **Anything reachable at a public address.** The policy is about addresses, not
   about authorisation. A tenant can still point a webhook at any public host,
   including one they control, and the request will carry whatever headers that
   sink sends. This is inherent to the feature.

3. **Ports.** No port restriction is applied. With `ALLOW_PRIVATE=true` or a CIDR
   exemption, a permitted internal address can be reached on any port, including
   non-HTTP services that tolerate an HTTP preamble. Keep the exemption list
   narrow.

4. **Response content reaching the tenant.** Refusals are reported; successful
   responses from permitted destinations are handled by each caller as before.
   This work did not change what is echoed back.

   Refusal messages carry the normalised hostname and resolved address, plus a
   reason from this package's own tables. They never carry the URL path, query or
   fragment. Handlers that echo a refusal at 400 extract the
   `egress.DestinationError` with `errors.As` rather than rendering the error
   chain, because `http.Client.Do` wraps delivery errors in a `*url.Error` that
   quotes the whole request URL — and for a Slack or Discord webhook that URL is
   the credential.

5. **Operator-configured destinations.** By design — see §1. If you set
   `SBOMHUB_NVD_URL` to an internal address, SBOMHub will connect to it.

5.1 **IPv6-only deployments behind a NAT64 on the local-use prefix.**
   `64:ff9b:1::/48` (RFC 8215) is blocked outright and no setting re-opens it.
   Unlike the well-known `64:ff9b::/96` and the operator-declarable prefixes
   above, RFC 8215 does not fix where the embedded IPv4 address sits inside it,
   so an address in it cannot be decoded and judged, and an opaque layout could
   be translating to the metadata address. If your network reaches IPv4 through
   a NAT64 on that prefix, these four integrations cannot reach anything through
   it. Use the well-known `/96`, or a prefix you can declare in
   `SBOMHUB_EGRESS_NAT64_PREFIXES`.

6. **Rows written before M50.** They are not re-validated on read, and nothing
   scans the tables. They do not need to be: enforcement moved to the connection,
   so an old row pointing somewhere internal is refused when it is next used, the
   same as a new one. But it means the refusal surfaces at delivery time rather
   than as a report you can run.

---

## 6. Where the code is

| File | Role |
|---|---|
| `apps/api/internal/egress/ip.go` | Address classification and the reason strings. |
| `apps/api/internal/egress/policy.go` | `Policy`, hostname matching, exemption parsing. |
| `apps/api/internal/egress/guard.go` | The dialer, the request-time round tripper, the redirect hook, `ValidateURL`. |
| `apps/api/internal/egress/policies.go` | The four per-purpose policies, and `OperatorControlled`. |
| `apps/api/cmd/server/egress.go` | Wiring from `SBOMHUB_EGRESS_*` to the guards. |
