# PIA WireGuard CLI

[![CI](https://github.com/M3t0r/pia-wg-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/M3t0r/pia-wg-rs/actions/workflows/ci.yml)
[![Rust](https://img.shields.io/badge/rust-1.88.0%2B-blue.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

A Rust-based command-line interface for managing Private Internet Access (PIA) WireGuard connections. This project replaces the `pia-foss/manual-connections` bash scripts with a less convoluted and more auditable solution.

## Features

- Generate WireGuard configurations for PIA servers
- List available PIA servers with optional filtering
- Measure latency to servers
- Verify VPN connection status
- Register and maintain a forwarded port on an active PIA tunnel
- Support for authentication via username/password or token

## Design Highlights

- All network-related code is isolated in a single file (`src/network.rs`) for improved auditability
- Easier to install / use than `pia-foss/manual-connections` 
- Can verify if VPN connection is still used, useful for custom kill switches
- No `sudo` required!

## Usage

```
Usage: pia-wg [OPTIONS] <COMMAND>

Commands:
  token    Login with user+password and echo a API token
  servers  List available servers
  create   Generates a new wireguard config
  check    Verify the VPN connection is active and used
  port     Register and maintain a forwarded port on an active PIA WireGuard tunnel
  help     Print this message or the help of the given subcommand(s)

Options:
  -t, --timeout <SECONDS>  Timeout for every request [default: 3]
      --debug              [env: DEBUG=]
  -h, --help               Print help
  -V, --version            Print version
```

For more detailed usage instructions, run `pia-wg help <COMMAND>`.

To use portforwarding:

```bash
pia-wg create --region $region --dns --port-forward > pia.conf
sudo wg-quick up ./pia.conf
pia-wg port register --conf pia.conf
pia-wg port activate --conf pia.conf # regreshes every 5 minutes
```

The port-forwarding commands have to be run with the WireGuard interface active.
`register` updates the config file if possible, otherwise prints the new config
to `stdout`. `activate` supports calling a callback executable (`echo` by
default). It receives the port, status, and message from the API respone as args
and environment variables. It is called on every iteration.

## Avoiding `sudo`

If you encounter the error "Operation not permitted (os error 1)", it's likely because the program needs special permissions to perform ICMP pings to find the closest VPN server to you. You have two options:

1. Run the program with `sudo` (not recommended for security reasons).
2. Grant the necessary capabilities to the executable (recommended):
   ```
   sudo setcap cap_net_raw=eip pia-wg
   ```
   This allows `pia-wg` to send ICMP packets without requiring root privileges.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
