# Xchonnect

Push-native, privacy-preserving signing relay protocol for Chia dApps and wallets.

Xchonnect lets a dApp send [CHIP-0002](https://github.com/Chia-Network/chips/blob/main/CHIPs/chip-0002.md)
signing requests to a mobile wallet and receive signatures back without persistent
connections, without custody, and without the relay learning message contents, Chia
addresses, or (with Oblivious HTTP) client IP addresses.

- Specification: [`docs/spec/xchonnect-spec.md`](docs/spec/xchonnect-spec.md)

## Licensing

| What | License |
|---|---|
| Source code (all crates and packages) | [Apache-2.0](LICENSE) |
| Specification and documents under `docs/` | [CC0 1.0](docs/LICENSE) (public domain dedication) |

Package manifests use the SPDX identifier `Apache-2.0`. Contributions are accepted
under the same terms; see [CONTRIBUTING.md](CONTRIBUTING.md).
