# Manual screenshots

Regenerates `docs/manual/*.png` from a local demo console with **fictional data only** (site "Demo office",
192.168.50.0/24, documentation IP 203.0.113.24, demo accounts). Never point it at real data.

```
python3 -m venv /tmp/gm && /tmp/gm/bin/pip install fastapi uvicorn cryptography webauthn pyjwt anthropic ldap3 dnspython websocket-client
/tmp/gm/bin/python tools/manual/demo_data.py . /tmp/gm-demo/runs
/tmp/gm/bin/python tools/manual/demo_server.py . /tmp/gm-demo &      # http://127.0.0.1:8765, signed in as a demo admin
/tmp/gm/bin/python tools/manual/shots.py docs/manual                  # needs Google Chrome
```
Check every screenshot for personal data before committing.
