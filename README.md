# netpy

more than implementation of netcat  🐱‍👤🔥

## Featutres 💻

- [ ] core written in `C`
- [X] TCP & UDP
- [ ] Backdoor (Reverse Shell)
- [ ] Honeypot
- [ ] File transfer
- [ ] Port forwarding
- [ ] Proxy
- [ ] Web Server
- [X] Port scanning
- [ ] Authentication
- [ ] Middelware
- [ ] Encription Connection
- [ ] `allow` & `deny` specific remote IP-address.
- [ ] Multi-Client
- [X] Build-in custom CLI
- [X] unit testing

## Structure

```bash
netpy
    └───core
        ├───cli
        └───connection
```

## Available Commands

- listen mode, for inbound connects

```bash
netpy -l 567
```

- Connecting to that port from another machine:

```bash
netpy -1.2.3.4 5676
```

- Setting up a remote shell listener:

```bash
netpy -v -e '/bin/bash' -l -p 1234 -t
```

- Scan range of ports from 80 to 127

```bash
netpy -z 127.0.0.1 80-127
```
