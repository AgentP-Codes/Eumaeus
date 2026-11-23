# Contributing

Thanks for helping. Eumaeus is small on purpose: no dependencies, plain Python 3.10+, and every change tested.

## Most useful right now

- **False alarms.** If an honest agent was flagged, tell us what it was doing (with made-up data). Avoiding false alarms matters more than anything else.
- **Decoys that give themselves away.** A decoy that looks different from the real records next to it, in any way an agent or a person could spot.
- **Connectors.** Results from MCP connectors that Eumaeus doesn't put decoys into, or handles badly. Paste a made-up example of what the connector returns.

## Making a change

```bash
git clone https://github.com/AgentP-Codes/Eumaeus
cd Eumaeus
pip install -e ".[dev]"
ruff check .
pytest -q
```

- Add a test for anything you change or fix. Use made-up data only, never real people, keys or accounts.
- Keep it free of dependencies.
- Alerts and messages are written for the person reading them: plain words, and say what happened and what to do.
- By contributing you agree that your contribution is licensed under the AGPL-3.0, like the rest of the project.

Security problems: please report them privately, as [SECURITY.md](SECURITY.md) explains.
