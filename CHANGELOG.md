# Changelog

## 0.1.0

First release.

- `eumaeus wrap -- <connector>`: decoys in front of any MCP connector. List and search results get a fake record shaped like the real ones, with the same made-up person throughout, ids that keep their prefix, emails that keep their domain, card numbers that pass the card check. The real app is never changed
- Each task gets its own decoys. Touches are graded: seen (nothing), opened (a notice, or an alert if the task has no business with that kind of record), used and sent out (blocked and alerted), and used in a later task (blocked and alerted)
- Blocked calls get an ordinary-looking error by default (`--honest-errors` to say why)
- Alerts: a private log (`eumaeus alerts`), the app's log, and an optional https webhook (`EUMAEUS_WEBHOOK_URL`). Alerts never carry a decoy's full values
- `eumaeus demo`: a made-up shop's support agent being tricked, and what Eumaeus does about it
- No dependencies beyond Python 3.10+. Messages are UTF-8 on every system
