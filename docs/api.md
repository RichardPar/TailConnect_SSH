# Admin HTTP API

The web portal is built on a JSON API, served by the hub on the same address (`https://hub.example.com/`). Everything the portal does, a script can do too.

- [Authentication](#authentication)
- [Conventions](#conventions)
- [Endpoints](#endpoints): [public](#public), [any account](#any-account), [operators](#operators-only)
- [Examples](#examples)

## Authentication

**Scripts: the admin token.** Create one on the hub. It's shown once, and it replaces the previous one:

```sh
sudo tcs-control admin-token
export TC_ADMIN_TOKEN=tc-admin-…
curl -H "Authorization: Bearer $TC_ADMIN_TOKEN" https://hub.example.com/api/v1/status
```

- **What the token can do.** It acts as an operator: it can see and change every account. Keep it like a root password. In particular, put it in an environment variable or a file, not on a command line that other users could see.
- **Replacing it.** Running `tcs-control admin-token` again makes the old token stop working at once.
- **Wrong tokens** answer 401, and they're limited like password guesses: 10 tries per client address, then one every 6 seconds. A client is one IPv4 address or one IPv6 /64.

**As an account: the session cookie.** `POST /api/v1/login` with a name and password sets an `HttpOnly` session cookie, valid for 12 hours, which acts as that account (a tenant or an operator). With curl, keep it in a cookie jar:

```sh
curl -c jar -H 'Content-Type: application/json' \
     -d '{"name":"alice","password":"…"}' https://hub.example.com/api/v1/login
curl -b jar https://hub.example.com/api/v1/machines
```

## Conventions

- **Paths.** `/api/v1/…` is the stable path. The portal's own pages use `/api/…`, which serves the same endpoints.
- **Request bodies** are JSON, sent with `Content-Type: application/json`.
- **Cookie sessions** must use that content type for every write. They're also refused if the request comes from another origin (`Origin` or `Sec-Fetch-Site`).
- **Requests with the admin token** may skip the body when there's nothing to send, for example `DELETE`. Browsers never add an `Authorization` header by themselves, so such requests can't be forged by another site.
- **Responses** are JSON. Errors are `{"error": "…"}` with a 4xx status:
  - 400: the request was wrong;
  - 401: not signed in, or a wrong token;
  - 403: operators only, or a refused cross-site request;
  - 404: not found;
  - 421: unknown host name;
  - 429: too many attempts.
- **Tenants** (accounts that aren't operators) see and act only on their own account's machines, keys, rules and shares. Other accounts' objects answer 404, as if they didn't exist. Operators act on every account.
- **Host names.** The hub answers only to host names it knows: IP addresses, `localhost`, its hostname, its certificate's names, the `--public-url` host and `--portal-host` names. Any other name gets 421.
- **IDs** are numbers from the lists. Times are Unix seconds.
- **Port specs** (`ports`) are `*`, or a comma-separated list of `22`, `8000-8100`, `tcp:443`, `udp:53` and `icmp`.

## Endpoints

### Public

| Method and path | Body | Result |
|---|---|---|
| `GET /api/v1/info` | | `{signup, domain, version}` |
| `POST /api/v1/login` | `{"name", "password"}` or `{"admin_token"}` | `{ok}`, and sets the session cookie |
| `POST /api/v1/logout` | | Ends the session |
| `POST /api/v1/signup` | `{"name", "password", "invite"?}` | `{status}`: `active` (and signed in) or `pending` (waiting for an operator). Refused when sign-up is `off`; needs `invite` when it's `invite`. |

### Any account

| Method and path | Body | Result |
|---|---|---|
| `GET /api/v1/status` | | `{version, domain, signup, account, operator, machines, online}`; operators also get `accounts` and `pending` |
| `GET /api/v1/me` | | `{name, operator, admin_token, domain, signup, server, tls_fingerprint}`. `name` is `null` for the admin token. `server` and `tls_fingerprint` are what `tc up` needs. |
| `POST /api/v1/me/password` | `{"current", "new"}` | Changes your password and ends your other sessions (not for the admin token) |
| `GET /api/v1/machines` | | `[{id, name, account, fqdn, ip, tags, exit_node, hostname, online, last_seen, created, traffic}]`. `traffic` is `{rx, tx, rx_rate, tx_rate, age}` (bytes, bytes/s, seconds since the report), or `null`. |
| `POST /api/v1/machines/{id}/tags` | `{"tags": "server, db"}` | `{tags}`. Replaces the machine's tags; `""` clears them. |
| `POST /api/v1/machines/{id}/rename` | `{"name"}` | `{name}` |
| `POST /api/v1/machines/{id}/exit-node` | `{"enabled": true}` | `{exit_node}`. Lets the machine route internet traffic for its account's machines, or stops it. Off until turned on; Linux machines only. |
| `GET /api/v1/machines/{id}/traffic` | | `{machine, reported, age, peers: [{peer, ip, rx, tx, rx_rate, tx_rate}]}`. For tenants, peers that aren't the account's own machines or linked by a share show as `another machine`, with no `ip`. |
| `DELETE /api/v1/machines/{id}` | | Removes the machine and its shares. It's cut off within a second. |
| `GET /api/v1/keys` | | `[{id, account, prefix, reusable, expires, used, state, created}]`; `state` is `active`, `used`, `expired` or `revoked` |
| `POST /api/v1/keys` | `{"expires_hours": 24, "reusable"?, "account"?}` | `{key, account}`. The key is shown only here. It expires after 1 hour to 1 year. `account` defaults to your own; operators may name any account. |
| `POST /api/v1/keys/{id}/revoke` | | Machines that joined with the key stay |
| `GET /api/v1/rules?account=NAME` | | `{account, rules: [{id, account, from, to, ports}]}`. `account` defaults to your own; operators may name any account. |
| `POST /api/v1/rules` | `{"from", "to", "ports", "account"?}` | `{id}`. `from` and `to` are `*`, `tag:NAME` or a machine name; `ports` defaults to `*`. An account's first rule switches it from "everything allowed" to "only what the rules allow". |
| `DELETE /api/v1/rules/{id}` | | Deleting an account's last rule allows everything again |
| `GET /api/v1/shares` | | `{by_me, with_me, links}`. Shares are `{id, node_id, machine, owner, account, ports, status, created}`, with `status` `pending` or `active`. Links are `{id, prefix, machine, ports, expires, used_by, state}`. |
| `POST /api/v1/shares` | `{"node_id", "account", "ports"?}` | `{id}`. Offers your machine to `account` (pending until accepted); `ports` defaults to `*`. |
| `POST /api/v1/shares/{id}/accept` | | The recipient accepts |
| `POST /api/v1/shares/{id}/ports` | `{"ports"}` | `{ports}`. The owner changes what the recipient may open. |
| `DELETE /api/v1/shares/{id}` | | The owner revokes, or the recipient declines or removes |
| `POST /api/v1/share-links` | `{"node_id", "days", "ports"?}` | `{code}`: a single-use `tc-share-…` link, valid for 1 to 90 days, shown only here |
| `DELETE /api/v1/share-links/{id}` | | Revokes an unused link |
| `POST /api/v1/share-links/redeem` | `{"code"}` | `{id}`: an active share for your account (not for the admin token) |

### Operators only

| Method and path | Body | Result |
|---|---|---|
| `GET /api/v1/accounts` | | `[{id, name, status, role, has_password, machines, created}]` |
| `POST /api/v1/accounts` | `{"name", "password"?, "operator"?}` | `{id, name}`. Without a password, the account can't sign in to the portal and is only for machines. |
| `POST /api/v1/accounts/{id}/status` | `{"status": "active" \| "suspended"}` | Approve a pending account, suspend, or reactivate. Suspending cuts the account's machines off and ends its sessions. |
| `POST /api/v1/accounts/{id}/role` | `{"role": "operator" \| "tenant"}` | Ends the account's sessions |
| `POST /api/v1/accounts/{id}/password` | `{"password"}` | Sets a password (at least 10 characters) and ends the account's sessions |
| `DELETE /api/v1/accounts/{id}` | | Deletes the account with its machines, keys, rules and shares |
| `GET /api/v1/invites` | | `[{id, prefix, expires, used_by, state, created}]` |
| `POST /api/v1/invites` | `{"days"}` | `{code}`: a single-use `tc-invite-…` code, valid for 1 to 90 days, shown only here |
| `DELETE /api/v1/invites/{id}` | | Revokes an unused invite |

An operator can't suspend, demote or delete their own account, so they can't lock themselves out.

## Examples

```sh
H="Authorization: Bearer $TC_ADMIN_TOKEN"
J="Content-Type: application/json"
HUB=https://hub.example.com

# A reusable key for alice, valid for a day:
curl -s -H "$H" -H "$J" -d '{"account":"alice","reusable":true,"expires_hours":24}' $HUB/api/v1/keys

# Machines that are offline:
curl -s -H "$H" $HUB/api/v1/machines | jq -r '.[] | select(.online|not) | .fqdn'

# The 5 machines that sent the most:
curl -s -H "$H" $HUB/api/v1/machines | jq -r 'map(select(.traffic)) | sort_by(-.traffic.tx) | .[:5][] | "\(.fqdn) \(.traffic.tx)"'

# Tag a machine and allow staff to reach it on SSH and HTTPS:
curl -s -H "$H" -H "$J" -d '{"tags":"server"}' $HUB/api/v1/machines/4/tags
curl -s -H "$H" -H "$J" -d '{"account":"richard","from":"tag:staff","to":"tag:server","ports":"tcp:22,tcp:443"}' $HUB/api/v1/rules

# Approve every pending sign-up:
for id in $(curl -s -H "$H" $HUB/api/v1/accounts | jq '.[] | select(.status=="pending") | .id'); do
    curl -s -H "$H" -H "$J" -d '{"status":"active"}' $HUB/api/v1/accounts/$id/status
done

# Remove a machine:
curl -s -X DELETE -H "$H" $HUB/api/v1/machines/7
```

With a self-signed certificate, give curl the certificate, `--cacert /var/lib/tailconnect-ssh-control/tls-cert.pem`, which needs `--resolve` if you connect by address. Or use `-k` on a network you trust.
