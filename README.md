# RustyAlias

![Logo](rustyalias.webp)

(_Shameless nip.io ripoff written in Rust_)

Wildcard DNS for any IP Address. RustyAlias allows you to map any IP Address to a hostname using the following formats (dot, dash or hex):

**Without a name:**

- **`10.0.0.1.example.com`** maps to **10.0.0.1**
- **`192-168-1-250.example.com`** maps to **192.168.1.250**
- **`a000803.example.com`** maps to **10.0.8.3**
- **`2a04-4e42-200--201.example.com`** maps to **2a04:4e42:200::201**

**With a name:**

- **`app.10.8.0.1.example.com`** maps to **10.8.0.1**
- **`app-116-203-255-68.example.com`** maps to **116.203.255.68**
- **`app-c0a801fc.example.com`** maps to **192.168.1.252**
- **`customer1.app.10.0.0.1.example.com`** maps to **10.0.0.1**
- **`customer2-app-127-0-0-1.example.com`** maps to **127.0.0.1**
- **`customer3-app-7f000101.example.com`** maps to **127.0.1.1**
- **`customer4.2a04-4e42-200--201.example.com`** maps to **2a04:4e42:200::201**

**Version TXT record:**

- **`version`** returns **RustyAlias v1.6.0**
- **`ver`** returns **RustyAlias v1.6.0**
- **`v`** returns **RustyAlias v1.6.0**

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

| Variable Name | Description                          | Default Value            |
| ------------- | ------------------------------------ | ------------------------ |
| `RUST_LOG`    | The logging level (`debug`, `info`). | None (no logging)        |
| `GLUE_NAME`   | Wildcard DNS name.                   | `ns.example.com`         |
| `GLUE_IP`     | DNS Server IPv4 Address              | `127.0.0.1`              |
| `SOA_NAME`    | Start of Authority name.             | `ns.example.com`         |
| `HOSTMASTER`  | Hostmaster name.                     | `hostmaster.example.com` |
| `SERIAL`      | SOA Serial number.                   | `1`                      |
| `REFRESH`     | SOA Refresh interval.                | `3600`                   |
| `RETRY`       | SOA Retry interval.                  | `1800`                   |
| `EXPIRE`      | SOA Expiration interval.             | `604800`                 |
| `MINIMUM`     | SOA Minimum TTL.                     | `3600`                   |
