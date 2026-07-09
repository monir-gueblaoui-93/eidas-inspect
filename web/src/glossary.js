/**
 * Plain-language educational copy for eIDAS terms, one short paragraph
 * each — surfaced via <Term> expandables wherever the term appears.
 */

export const GLOSSARY = {
  qualified: {
    label: 'Qualified',
    body: "The highest trust level under EU law (eIDAS). A qualified signature, seal, or timestamp is legally presumed as reliable as a handwritten signature, and can only be issued by a supervised, accredited provider using certified technology.",
  },
  qes: {
    label: 'QES (Qualified Electronic Signature)',
    body: 'A qualified electronic signature is applied by an individual person to sign a document. Under EU law it carries the same legal weight as a handwritten signature, and is recognized across all EU member states.',
  },
  qseal: {
    label: 'QSeal (Qualified Electronic Seal)',
    body: "A qualified electronic seal is applied by an organization, not a person, to guarantee a document's origin and that it hasn't been altered — the digital equivalent of a corporate stamp, backed by cryptography.",
  },
  trustedList: {
    label: 'EU Trusted List',
    body: 'Every EU country publishes an official list of the certificate providers it supervises. eidas-inspect checks the document\'s signer against these lists to confirm the provider is genuinely accredited, not just self-declared.',
  },
  timestamp: {
    label: 'Qualified timestamp',
    body: 'A qualified timestamp is issued by an accredited time-stamping authority and proves a document existed, unchanged, at a specific moment — carrying the same legal trust as a qualified signature.',
  },
  ksiSeal: {
    label: 'KSI seal',
    body: "A KSI seal is produced by Keyless Signature Infrastructure (KSI), a sealing technology that works differently from the certificate-based signatures elsewhere on this page. Instead of relying on a certificate authority you have to trust, it anchors a document into a shared, publicly witnessed hash-chain record that anyone can independently check. Scrive is one example of a service that has produced documents sealed this way. A KSI seal is not currently confirmed as an eIDAS-qualified seal by this tool.",
  },
}
