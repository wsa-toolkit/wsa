# Contributing to WSA

## Reporting bugs

Open an issue at https://github.com/wsa-toolkit/wsa/issues with:

- Output of `python3 -m py_compile wsa.py`
- Last 20 lines of `/tmp/wsa_debug.log` at the moment of failure
- Your distribution + kernel version (`uname -a`, `cat /etc/os-release`)
- Adapter model + `iw list | grep -A 5 "Supported interface modes"`

## Security reports

Do not open a public issue for vulnerabilities. Email the maintainer
directly: abdelkader.astite@gmail.com. Expect a first reply within 7 days.

## Pull requests

- One logical change per PR
- Run `python3 -m py_compile wsa.py` before submitting
- If you change the UI, include a screenshot
- If you add a protocol, include references (IEEE / IETF / NIST)

## Style

WSA is a single-file Python script with deliberate formatting:
- ASCII diagrams must not be reflowed
- Long method strings are intentional
- `black` and `flake8` are not used — `py_compile` is the gate

## License

By contributing, you agree your contribution is licensed under
GPL-2.0-or-later.
