# RustyAlias

![Logo](rustyalias.webp)

- [RustyAlias](#rustyalias)
  - [Hex IPv4](#hex-ipv4)
  - [Public Demo](#public-demo)
  - [Docker Compose](#docker-compose)
  - [Podman (Docker)](#podman-docker)
  - [Dev](#dev)
  - [Environment Variables](#environment-variables)
  - [Todo](#todo)

(_Shameless nip.io ripoff written in Rust_)

Wildcard DNS for any IP Address. RustyAlias allows you to map any IP Address to a hostname using the following formats (dot, dash or hex):

![demo](demo.gif)

**Without a name:**

- **`10.0.0.1.example.com`** maps to **10.0.0.1**
- **`192-168-1-250.example.com`** maps to **192.168.1.250**
- **`0a000803.example.com`** maps to **10.0.8.3** (hex IPv4)
- **`2a04-4e42-200--201.example.com`** maps to **2a04:4e42:200::201**

**With a name:**

- **`app.10.8.0.1.example.com`** maps to **10.8.0.1**
- **`app-116-203-255-68.example.com`** maps to **116.203.255.68**
- **`app-c0a801fc.example.com`** maps to **192.168.1.252** (hex IPv4 in the label)
- **`customer1.app.10.0.0.1.example.com`** maps to **10.0.0.1**
- **`customer2-app-127-0-0-1.example.com`** maps to **127.0.0.1**
- **`customer3-app-7f000101.example.com`** maps to **127.0.1.1**
- **`customer4.2a04-4e42-200--201.example.com`** maps to **2a04:4e42:200::201**

**Dual-stack** (IPv4 and IPv6 as separate labels, either order):

- **`127-0-0-1.2a04-4e42-200--201.example.com`** → **A 127.0.0.1**, **AAAA 2a04:4e42:200::201**
- **`2a04-4e42-200--201.127-0-0-1.example.com`** → same
- **`app.127-0-0-1.2a04-4e42-200--201.example.com`** → same
- **`7f000001.2a04-4e42-200--201.example.com`** → same (hex IPv4)

### Hex IPv4

An IPv4 address can be written as **exactly eight hexadecimal digits**: each octet becomes two hex characters, in network order (no separators).

| Dotted decimal | Octets (decimal) | Octets (hex) | Label |
| -------------- | ---------------- | ------------ | ----- |
| `10.0.8.3` | 10, 0, 8, 3 | `0a`, `00`, `08`, `03` | `0a000803` |
| `192.168.1.252` | 192, 168, 1, 252 | `c0`, `a8`, `01`, `fc` | `c0a801fc` |
| `127.0.0.1` | 127, 0, 0, 1 | `7f`, `00`, `00`, `01` | `7f000001` |

The eight-digit token can be a label on its own (`0a000803.example.com`) or appear inside a hyphenated name (`app-c0a801fc.example.com`). Digits are case-insensitive (`C0A801FC` works the same).

Generate a hex label from a dotted IPv4 address:

```bash
# Python
python3 -c 'import ipaddress,sys; print(ipaddress.IPv4Address(sys.argv[1]).packed.hex())' 192.168.1.252
# → c0a801fc

# Perl
printf '%02x%02x%02x%02x\n' 192 168 1 252
# → c0a801fc

# Bash (IFS splits the address)
IFS=. read -r a b c d <<< '192.168.1.252'
printf '%02x%02x%02x%02x\n' "$a" "$b" "$c" "$d"
```

**Version TXT record:**

- **`version`** returns **RustyAlias v1.6.0**
- **`ver`** returns **RustyAlias v1.6.0**
- **`v`** returns **RustyAlias v1.6.0**

## Public Demo

A public demo instance is available at **`nip.nu`**. You can resolve any IP Address against it using the formats described above, for example:

- **`app.127.0.0.1.nip.nu`** maps to **127.0.0.1**
- **`192-168-1-250.nip.nu`** maps to **192.168.1.250**
- **`app-c0a801fc.nip.nu`** maps to **192.168.1.252**
- **`2a04-4e42-200--201.nip.nu`** maps to **2a04:4e42:200::201**
- **`127-0-0-1.2a04-4e42-200--201.nip.nu`** → **A 127.0.0.1**, **AAAA 2a04:4e42:200::201**

Try it out:

```bash
dig app.127.0.0.1.nip.nu

...
;; QUESTION SECTION:
;app.127.0.0.1.nip.nu.  IN  A

;; ANSWER SECTION:
app.127.0.0.1.nip.nu. 60    IN  A   127.0.0.1
```

## Docker Compose

```bash
docker compose up -d
```

## Podman (Docker)

```bash
podman run --rm -d \
--name rustyalias \
-p 53:5053/udp \
-e RUST_LOG=info \
-e GLUE_NAME=ns.example.com \
-e SOA_NAME=ns.example.com \
-e HOSTMASTER=hostmaster.example.com \
ghcr.io/stenstromen/rustyalias:latest
```

## Dev

```bash
RUST_LOG=debug cargo run
```

```bash
dig @127.0.0.1 -p 5053 1337-c0a801fc.example.com

...
;; QUESTION SECTION:
;1337-c0a801fc.example.com. IN  A

;; ANSWER SECTION:
1337-c0a801fc.example.com. 60   IN  A   192.168.1.252
```

## Environment Variables

This project uses the following environment variables:

| Variable Name         | Description                                                             | Default Value            |
| --------------------- | ----------------------------------------------------------------------- | ------------------------ |
| `RUST_LOG`            | The logging level (`debug`, `info`).                                    | None (no logging)        |
| `GLUE_NAME`           | Wildcard DNS name / zone apex.                                          | `ns.example.com`         |
| `GLUE_IP`             | DNS server IPv4 address (apex A / in-bailiwick glue).                   | `127.0.0.1`              |
| `GLUE_IP6`            | DNS server IPv6 address (apex AAAA / glue). Empty disables.             | (unset)                  |
| `SOA_NAME`            | SOA MNAME (primary nameserver hostname).                                | `ns.example.com`         |
| `NS_NAMES`            | Comma-separated apex NS set. Defaults to `SOA_NAME` if unset.           | (same as `SOA_NAME`)     |
| `HOSTMASTER`          | Hostmaster name.                                                        | `hostmaster.example.com` |
| `SERIAL`              | SOA Serial number.                                                      | `1`                      |
| `REFRESH`             | SOA Refresh interval.                                                   | `3600`                   |
| `RETRY`               | SOA Retry interval.                                                     | `1800`                   |
| `EXPIRE`              | SOA Expiration interval.                                                | `604800`                 |
| `MINIMUM`             | SOA Minimum TTL.                                                        | `3600`                   |
| `SPF`                 | Apex SPF TXT record. Empty disables.                                    | `v=spf1 -all`            |
| `DMARC`               | `_dmarc.<zone>` TXT record. Empty disables.                             | `v=DMARC1; p=reject;`    |
| `RATE_LIMIT_REQUESTS` | Max requests per source IP per window. `0` disables rate limiting.      | `0`                      |
| `RATE_LIMIT_SECONDS`  | Length of the rate-limit window in seconds. `0` disables rate limiting. | `0`                      |

`SPF` and `DMARC` default to a “this zone does not send mail” posture, which is appropriate for a wildcard IP DNS domain. Set either variable to an empty string to omit that record.

For a domain delegated to two nameservers (e.g. `.nu` / `.se`), set the child NS set to match the parent:

```bash
NS_NAMES=ns.addr.se,ns1.addr.se SOA_NAME=ns1.addr.se GLUE_IP6=2a01:4f9:c012:6a18::1
```

UDP responses that exceed the client’s EDNS size (or 512 bytes without EDNS) are truncated with the `TC` bit set so resolvers retry over TCP.

Rate limiting is **off by default**. To enable, set both variables to non-zero values. For example, to allow at most 20 requests per source IP every 1 second:

```bash
RATE_LIMIT_REQUESTS=20 RATE_LIMIT_SECONDS=1 cargo run
```

Rate-limited queries are silently dropped (sending a response to a possibly spoofed source would amplify attacks).

## Todo

- [x] Public demo instance
- [x] Docker Compose
- [ ] Cloudflare integration
- [x] Rate limit
- [x] ARM64 support
