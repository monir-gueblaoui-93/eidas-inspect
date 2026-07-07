# eidas-inspect

A hosted service that verifies digital signatures, seals, and timestamps in PDFs against the eIDAS framework — and explains the result in plain language.

## Why

Existing validators are either impenetrable (the EU's own DSS tool dumps a wall of ASN.1 and certificate chains on you) or an unexplained checkmark (Adobe just tells you it's "signed" and moves on). Neither helps someone who actually needs to know whether a document can be trusted.

eidas-inspect's bet is radical legibility: an opinionated traffic-light verdict a non-expert can act on immediately, backed by expandable technical detail for anyone who wants to see the actual chain of reasoning.

## Status

Work in progress, being built in public over one week with Claude Code.

**Done**
- Core validation package (`core/`, pyHanko-based)
- Signature, seal, and timestamp discovery
- Integrity and tamper detection, with PAdES-LTA awareness (so legitimate long-term-archival extensions aren't misreported as tampering)
- qcStatements classification per ETSI EN 319 412-5, with a conservative QUALIFIED policy
- 12/12 tests passing

**Planned**
- EU Trusted List verification
- OCSP/CRL revocation checking
- Verdict engine (combining trust chain, revocation, and cert claims into one verdict)
- FastAPI backend
- Web UI
- PDF report export
- Deployment

## Planned architecture

`core/` is a pure-Python validation engine with no web dependencies — pyHanko handles the crypto and PAdES mechanics, and this package adds qcStatements parsing, EU Trusted List matching, and plain-language verdict mapping on top. `api/` will be a FastAPI wrapper around it, strictly ephemeral: documents are processed in memory and never touch disk. `web/` will be a React frontend for the actual verification flow.

## Privacy

Uploaded documents are never written to disk or logged. Ever.

## Local development

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e "core[dev]"
pytest core/tests
```

## Limitations

This is an informational tool, not a qualified validation service under eIDAS Article 33, and nothing it says is legal advice. It's a personal project — use your own judgment for anything that matters.

## License

MIT — see [LICENSE](LICENSE).
