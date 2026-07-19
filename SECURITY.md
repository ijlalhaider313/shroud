# Security Policy

## About this tool

`shroud` is an **offensive security research and authorized-penetration-testing**
tool. It generates Windows payloads that implement documented process-injection
techniques with userland EDR-evasion layers. It exists to help red teamers,
detection engineers, and students understand and test those techniques.

## Authorized use only

Do **not** use `shroud` against any system you do not own or are not explicitly
authorized to test. Unauthorized use is illegal and unethical. By using this
tool you accept full responsibility for compliance with all applicable laws and
your engagement scope. See [LICENSE](LICENSE) and the project README.

`generate` and `build` are gated behind a one-time `./shroud authorize`, which
records a local acknowledgment marker. This is a reminder, not permission.

## Reporting a vulnerability in shroud itself

If you find a security issue **in the shroud codebase** (e.g. it mishandles
shellcode, corrupts projects, or has a defect that could be exploited by a
crafted input), please report it responsibly:

- Open a private security advisory on the GitHub repository, **or**
- email the maintainer directly with details.

Do **not** open a public issue for security vulnerabilities in the tool.

Please include the steps to reproduce and the `shroud` version (`./shroud` with
no args, or the `__version__` in `lib/__init__.py`).

## Scope of support

This project documents evasion techniques that are, by design, meant to evade
detection. "This payload bypassed / was caught by my EDR" is **expected
behavior**, not a vulnerability, and is out of scope for this policy.
