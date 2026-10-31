# Decoys (canary tokens)

Per site (Settings › Sites › Settings › Decoys). A decoy looks valuable and is never used legitimately, so any use means
someone is looking around where they shouldn't (Thinkst Canary, Horizon3 Tripwires). Guardian creates them; you place
them. Nothing is planted automatically.

| Kind | You place | Alert when |
|---|---|---|
| Tracking link | The URL in a wiki page, an e-mail draft, a bookmark | The link is opened (it shows an ordinary 404 page) |
| Fake admin login | Three lines (portal URL, user, password) in passwords.txt, a script, a password-manager export | The portal is visited (medium); someone signs in with the planted password (high) |
| Bait Word document | IT-passwords.docx on a share or backup folder | Word opens it and fetches its linked image (also contains fake credentials for the login above) |

Each hit records time, address, browser and what happened (never a submitted password), and goes to your alert
channels and the SIEM. Alerts are limited to one per decoy every 10 minutes, except a sign-in with the planted
password, which always alerts. Remove a decoy to make its address go quiet; remove it from where you placed it too.

Decoys need Guardian's address to be reachable from where the decoy would be used (the customer's network or the
internet). Word may block linked images in files from the internet (Protected View); tracking links and the fake
login don't depend on that.
