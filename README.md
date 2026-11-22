# Eumaeus

*Pronounced yoo-MEE-us.*

**Decoys for AI agents.** Eumaeus slips fake records into what an AI agent sees: a payment, a customer, a Slack user, an API key, shaped exactly like the real ones. No real job ever needs a decoy, so the moment an agent tries to refund one, email one or send its details anywhere, it has almost certainly been tricked by something it read. Eumaeus blocks that action and tells you which task it was.

> [!WARNING]
> **Early release (0.1).** Try it with test accounts and made-up data first. It's a tripwire, not a wall: it tells you when an agent has been tricked, and stops actions that use a decoy, but it doesn't stop a tricked agent from doing other harm with real data. Don't rely on it as your only protection. Provided "as is", without warranty, under the [AGPL-3.0 licence](LICENSE).

## Why

Honeytokens (fake credentials and records that only an attacker would touch) are one of the few security alarms that are almost never wrong. Existing ones guard cloud accounts and files against people. Eumaeus does the same for the apps a small business's AI agent works in (Stripe, HubSpot, Slack and the like) and for the way agents get attacked: a prompt injection hidden in an email, a web page or a document, or a patient attacker who behaves normally until the moment they don't. Behaving normally doesn't help them here: a real job never touches a decoy.

## How it works

Eumaeus sits between your agent app (Claude Desktop, or any app that uses MCP connectors) and one connector:

- **List and search results get a decoy**, a copy of one of the real records with every identifying value replaced: ids keep their prefix and length, emails keep their domain, card numbers keep their length and pass the card check, and the same made-up person appears throughout. Single-record lookups and the results of actions are never touched.
- **The real app is never changed.** Decoys only ever exist in what the agent is shown, so nothing appears in your reports, accounts or mailing lists.
- **Each task gets its own decoys**, so an alert says exactly which session was tricked, and a decoy someone learned about earlier is useless later.
- **Every touch is graded:**

| What the agent did | What Eumaeus does |
| --- | --- |
| Saw a decoy in a list | Nothing: agents read lists |
| Opened a decoy record | Shows it (so nothing gives it away) and notes it. An alert if this kind of task has no business with that kind of record (a support agent opening API keys) |
| Used a decoy (refund it, email it, update it) | Blocks it and alerts |
| Sent a decoy's details out (in a message, an email body) | Blocks it and alerts |
| Used a decoy from an **earlier** task | Blocks it and alerts: something is carrying data between tasks (a memory, a connector, a person) |

Blocked calls get an ordinary-looking "not found" error by default, so the agent (and whoever is steering it) isn't told it hit a trap.

## Try it

```bash
pip install git+https://github.com/AgentP-Codes/Eumaeus
eumaeus demo          # a support agent for a made-up shop gets tricked; watch what happens
```

## Use it with Claude Desktop

Put `eumaeus wrap ... --` in front of a connector's command in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "stripe": {
      "command": "eumaeus",
      "args": ["wrap", "--task", "refunds", "--", "npx", "-y", "@stripe/mcp", "--tools=all"]
    }
  }
}
```

`--task` says what the agent does: `support`, `refunds`, `bookkeeping`, `sales`, `dev` or `general` (the default). Opening a decoy of a kind the task never needs (payments in a support task, keys in anything but `dev`) is an alert.

## Alerts

- Every alert and notice goes to `~/.eumaeus/alerts.jsonl` (private to your user). `eumaeus alerts` shows them; `eumaeus alerts --all` includes notices.
- Alerts also go to the app's log (standard error).
- To get them in Slack, create an [incoming webhook](https://api.slack.com/messaging/webhooks) and set it in the environment as `EUMAEUS_WEBHOOK_URL`. Never put it in a file in your project. It must be https; redirects are never followed.

Alerts never contain a decoy's full values, only enough of the start to find it.

## Limits

- **It catches the use of decoys, not everything a tricked agent does.** An agent fooled into misusing *real* data won't trip it unless it also touches a decoy. For limits on where real data can go, pair it with a data vault such as [Eurycleia](https://github.com/AgentP-Codes/Project-Eurycleia).
- **Only results that are lists of records get decoys**, in JSON. A connector that returns plain text, or one record at a time, gets none.
- **Recognising a decoy** looks for its distinctive values (ids, emails, card and phone numbers, keys, full names), as written or in upper or lower case. A decoy rewritten heavily enough (spelled out, encoded) won't be recognised.
- **Your own files are part of the defence.** `~/.eumaeus` holds the key that recognises old decoys. An agent that can read or write files in your account could learn from it; don't give the agent you're protecting access to that folder.
- **A decoy can, rarely, be opened by an honest agent** browsing a list. That's a notice, not an alert, unless the task has no business with that kind of record.
- Tested with simulated connectors and made-up data. Not independently audited.

## How it was built

Eumaeus was designed and directed by @AgentP-Codes, and written with the help of Claude (Anthropic's AI) using Claude Code. It comes from the same project as [Eurycleia](https://github.com/AgentP-Codes/Project-Eurycleia), a data vault for AI agents. In the *Odyssey*, Eumaeus is the loyal swineherd who keeps watch over the household while its master is away, and helps expose the intruders.

## Contributing and security

Issues and ideas are welcome. Please report security problems privately: see [SECURITY.md](SECURITY.md).

## Licence

[GNU Affero General Public License v3.0 only](LICENSE). If you run a modified version as a network service, you must offer its source to its users.
