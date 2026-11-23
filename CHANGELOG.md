# Changelog

## 0.2.1

- **A customer sent their own records isn't an alarm.** A decoy planted in a list inside someone's record (a customer's own payments, say) and sent back only to that person is now a notice, and the message goes. Sent to anyone else, or to them with anyone else copied in, it's still blocked and alerted. Found in a test run of the live setup, where every reply that listed a customer's payments raised an alarm

## 0.2.0

- **Lockdown after a decoy is used.** The agent has been tricked, so every action in every session on the computer is refused until a person lifts it (`eumaeus clear`). Reading still works. `--no-lock` blocks only the action that used the decoy. `eumaeus status` shows whether anything is locked down
- **Encoded and disguised decoys are recognised**: base64, hex, URL and HTML encoding, spacing, reversed text, look-alike and invisible characters
- **Watch mode** (`--watch`): alerts only, never blocks or locks. For trials on a live setup
- **Client names** (`--client`): shown in every alert, for people who look after several businesses
- **Teams and JSON webhooks** (`EUMAEUS_WEBHOOK_FORMAT=teams` or `json`) as well as Slack
- **Linked with Eurycleia** (`eumaeus link eurycleia`, needs Eurycleia 0.8.0): a decoy used anywhere locks down both, either can lift it, and Eurycleia reports connectors whose tools changed. Signals are signed files on the computer; nothing goes over the network
- **`eumaeus ui`**: a page on your computer only, with the lockdown and a button to lift it, a timeline from both products, and connectors waiting for approval. It needs a secret made fresh each time, and refuses other websites
- Fixed: alerts on Windows are written in UTF-8 (a name like José, or "…", could stop the connector); a decoy's values can never repeat a real value or an earlier decoy's, and a decoy person never has a real customer's full name

## 0.1.0

First release.

- `eumaeus wrap -- <connector>`: decoys in front of any MCP connector. List and search results get a fake record shaped like the real ones, with the same made-up person throughout, ids that keep their prefix, emails that keep their domain, card numbers that pass the card check. The real app is never changed
- Each task gets its own decoys. Touches are graded: seen (nothing), opened (a notice, or an alert if the task has no business with that kind of record), used and sent out (blocked and alerted), and used in a later task (blocked and alerted)
- Blocked calls get an ordinary-looking error by default (`--honest-errors` to say why)
- Alerts: a private log (`eumaeus alerts`), the app's log, and an optional https webhook (`EUMAEUS_WEBHOOK_URL`). Alerts never carry a decoy's full values
- `eumaeus demo`: a made-up shop's support agent being tricked, and what Eumaeus does about it
- No dependencies beyond Python 3.10+. Messages are UTF-8 on every system
