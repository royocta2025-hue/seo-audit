// Tempelkan URL Worker Anda pada integrasi XML berikutnya.
const SEO_AUDIT_WORKER = "https://seo-audit-api.YOUR-SUBDOMAIN.workers.dev";

// Kontrak frontend:
// GET  `${SEO_AUDIT_WORKER}/challenge` -> challenge ALTCHA v3
// POST `${SEO_AUDIT_WORKER}/audit`
// body: { url: "https://example.com", altcha: "BASE64_PAYLOAD" }
// response: { ok, requestedUrl, finalUrl, status, contentType, bytes, html }
