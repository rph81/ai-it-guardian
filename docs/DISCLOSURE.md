# Vulnerability-disclosure page

Per site (Settings › Sites › Settings › Disclosure). NIS2 Article 21 and ISO 27001 expect a way for outsiders to report
security weaknesses; HackerOne and Bugcrowd sell this as a "VDP".

- **Public page** at `https://<guardian>/vdp/<random link>`: the customer's name, the policy (editable; a sensible
  good-faith default), and a form: title, affected address, description, optional contact. No sign-in.
- **security.txt** at `…/security.txt` with Contact, Policy, Expires (11 months) and languages, for the customer to
  publish at `https://<their domain>/.well-known/security.txt`. Renew it yearly.
- **Reports** appear in the Disclosure tab and trigger your alert channels. **Add to Fix plan** files one into the
  site's latest assessment (choose the severity); **Dismiss** keeps it for the record.
- **Safety:** reports are plain text (never rendered as HTML), size-capped, limited to 5 per hour per address and 50 a
  day per site. Reporter IP addresses are not stored. **New link** retires the old address at once; switching the page
  off makes it answer 404.

The page needs Guardian's address to be reachable from the internet. If it isn't published, publish a security.txt
with an e-mail contact only.
