# RustyAlias

(*Shameless nip.io ripoff written in Rust*)

Wildcard DNS for any IP Address. RustyAlias allows you to map any IP Address to a hostname using the following formats (dot, dash or hex):

**Without a name:**

- **`10.0.0.1.example.com`** maps to **10.0.0.1**
- **`192-168-1-250.example.com`** maps to **192.168.1.250**
- **`a000803.example.com`** maps to **10.0.8.3**

**With a name:**

- **`app.10.8.0.1.example.com`** maps to **10.8.0.1**
- **`app-116-203-255-68.example.com`** maps to **116.203.255.68**
- **`app-c0a801fc.example.com`** maps to **192.168.1.252**
- **`customer1.app.10.0.0.1.example.com`** maps to **10.0.0.1**
- **`customer2-app-127-0-0-1.example.com`** maps to **127.0.0.1**
- **`customer3-app-7f000101.example.com`** maps to **127.0.1.1**

## Dev

```bash
RUST_LOG=debug cargo run
```

```bash
dig @127.0.0.1 -p 5053 1337-c0a801fc.example.co
```
