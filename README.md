# Encrypted report intake prototype

Documentation and synthetic tests only. **Not accepting real reports.** Never publish reporter details, real vehicle plates, photos, credentials, keys or tokens here, in plaintext or encrypted, until the pilot has an approved go-live.

This repository explores a public encrypted mailbox: one logical package contains an evidence JPEG and report JSON, encrypted on-device; only a separate private worker could decrypt. A public encryption key does not identify or authorize a sender. Device signatures, enrolled GitHub identities, exact approval, revocation, byte caps and durable duplicate guards are required.

Current status: eight offline crypto/package experiments and eight intake-boundary tests passed. Live GitHub App device-flow permissions, chunk acceptance, photo legibility, Android interoperability and private-worker triggering are unproven. No municipal calls or filing workflow in this repository. Public ciphertext and author/time/size metadata can be archived indefinitely. Do not use this as a production service.

Protocol: [PROTOCOL.md](PROTOCOL.md). Experimental test script: [prototype.py](prototype.py). Test dependencies are Python cryptography and Pillow. Run `python prototype.py` locally. Keys are generated transiently for synthetic tests and not written to disk.

No license selected. No permission to redistribute production code is implied.

Boundary test source: [intake_validation.py](intake_validation.py), run `python intake_validation.py`. Uses only Python standard library. This validates untrusted transport structure, not real identity enrollment, crypto authenticity or filing approval.
