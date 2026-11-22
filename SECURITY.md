# Security

Please report security problems **privately**, through GitHub: this repository's **Security** tab, then **Report a vulnerability**. Don't open a public issue.

Include what you found, how to reproduce it (with made-up data), and what an attacker could do with it. You'll get an answer within a week. Fixes are released as soon as they're tested, and reporters are credited unless they'd rather not be.

**Things worth reporting:** a way for a decoy to be told apart from real records, a way to use a decoy without it being caught, a way to make Eumaeus raise false alarms on normal work, anything that lets an agent or a connector read or change `~/.eumaeus`, and anything that leaks a decoy's values into alerts or logs.
