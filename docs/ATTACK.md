# MITRE ATT&CK mapping

Guardian maps every open finding to the [MITRE ATT&CK](https://attack.mitre.org) Enterprise techniques it would let an
attacker use. It answers "what could someone do with this?" in the language security teams, insurers and auditors use.

## Where techniques come from

1. **Risk analyst.** While ranking findings it reads `attack_catalog` (the techniques Guardian knows, with the rules'
   suggestion for each finding) and sets up to five techniques per finding with `set_priority`. Unknown IDs are refused.
2. **Rules.** Findings the analyst hasn't mapped (scanner-only runs, imported Nessus/Qualys/… results) get techniques
   from pattern rules on the title and evidence (`guardian/attack.py`), e.g. RDP → T1021.001 + T1133, no MFA → T1078,
   T1110, T1621, mail forwarding → T1114.003. Ransomware-linked findings add T1486; internet-exposed ones add T1190.
3. **Attack paths.** The Attack paths agent can tag each step of a path with a technique.

The catalogue covers about 55 techniques across 13 tactics: the ones the weaknesses Guardian finds lead to. Each technique
is shown under its main tactic. IDs and names follow ATT&CK Enterprise; check attack.mitre.org for the current version.

## Where you see it

| Place | What |
|---|---|
| Run detail › **ATT&CK** | Heat map: tactics with findings as columns, techniques as cells, darker = more findings. Click a cell for the findings and attack paths that use it |
| Fix plan | Technique chips on each row, linked to attack.mitre.org |
| Attack paths | Technique per step |
| HTML report | "What an attacker could do" section; ATT&CK line on each finding |
| Compliance PDF | Technique IDs per finding in Appendix A |
| API | `GET /api/runs/{run}/attack` (matrix), `attack` field in `/api/runs/{run}/tracking` |
