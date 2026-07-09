# KSI test fixtures

Extracted from Guardtime's own official demo file
(`demo/signed.pdf` in [guardtime/ksi-pdf-verifier](https://github.com/guardtime/ksi-pdf-verifier),
Apache-2.0), not fabricated -- a genuine, internally-consistent KSI
signature over genuine document bytes, produced by Guardtime themselves
for exactly this purpose (demoing/testing their own verifier).

- `demo-signature.ksig` -- the raw KSI signature token, byte-for-byte as
  found in the demo PDF's `/Contents` hex string (hex-decoded).
- `demo-covered.bin` -- the demo PDF's own `/ByteRange`-covered bytes
  (`/ByteRange [0 96444 112830 7627]`), i.e. exactly what a correct
  discovery implementation would hash and hand to `ksi-tool` via `-f`.

Signed 2019-04-05 (unextended -- no publication record), so
publication-based verification against it is expected to come back `NA`
("not yet extended"), not `OK`. See `test_ksi_tool_integration.py`.
