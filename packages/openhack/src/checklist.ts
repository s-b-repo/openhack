/**
 * Built-in web/API/infra testing methodology — the curated union of the OWASP Web
 * Security Testing Guide (WSTG), the PortSwigger Web Security Academy topic list,
 * HackTricks, and the OWASP API Security Top 10. Each class lists concrete
 * techniques so the coverage tracker can assert that "every type of test that can
 * be done" has actually been attempted on every discovered endpoint × method.
 *
 * This is data, not prose — `Coverage` (coverage.ts) and the automode loop consult
 * it to drive testing toward untested cells and to compute a coverage percentage.
 */
export namespace Checklist {
  export type Category = "recon" | "auth" | "access-control" | "injection" | "logic" | "client" | "infra" | "api" | "crypto"

  export interface Technique {
    id: string
    name: string
  }

  export interface VulnClass {
    id: string
    name: string
    category: Category
    /** HTTP methods this class is worth testing on ("*" = any). */
    methods: string[]
    /** Source references (WSTG ids, PortSwigger topic, HackTricks, OWASP). */
    refs: string[]
    techniques: Technique[]
    /**
     * Other Checklist class ids known to CHAIN with this one (combination
     * testing). Used by `Combinations.chainPairs()` to detect untested
     * class-pair coverage — e.g. sqli → auth (auth-bypass via injection),
     * ssrf → api-bola-bfla (SSRF-to-internal-API), upload → cmdi (webshell
     * → RCE). Optional and additive; absent means "no chain hints".
     */
    chainHints?: string[]
    /** OWASP WSTG id (e.g. "WSTG-INPV-05"). Structured mirror of the string in `refs`. */
    wstgId?: string
    /** Key into `packages/openhack/knowledge/hacktricks-index.json`. */
    hacktricksSlug?: string
  }

  const T = (id: string, name: string): Technique => ({ id, name })

  export const CLASSES: VulnClass[] = [
    // ── Recon / information disclosure ──────────────────────────────────────
    { id: "info-disclosure", name: "Information disclosure", category: "recon", methods: ["*"],
      refs: ["WSTG-INFO", "PortSwigger: Information disclosure", "HackTricks: recon"], techniques: [
        T("version-banner", "Software/version + banner disclosure"), T("metafiles", "robots.txt/sitemap/.well-known/security.txt"),
        T("dir-listing", "Directory listing enabled"), T("backup-source", "Backup/source/.git/.env/.DS_Store exposure"),
        T("verbose-errors", "Verbose errors / stack traces / debug"), T("comments-metadata", "HTML comments / JS source maps / metadata"),
        T("api-docs", "Swagger/OpenAPI/GraphQL introspection exposure")] },
    { id: "user-enum", name: "User / resource enumeration", category: "recon", methods: ["GET", "POST"],
      refs: ["WSTG-IDNT-04", "PortSwigger: Authentication"], techniques: [
        T("login-oracle", "Username enumeration via login/reset response/timing"), T("rest-users", "REST/user API enumeration")] },

    // ── Authentication ──────────────────────────────────────────────────────
    { id: "auth", name: "Authentication", category: "auth", methods: ["POST", "GET"],
      refs: ["WSTG-ATHN", "PortSwigger: Authentication", "HackTricks: auth"], techniques: [
        T("default-weak-creds", "Default / weak / reused credentials"), T("brute-no-lockout", "No rate-limit / lockout (brute force)"),
        T("logic-bypass", "Auth logic bypass (2FA skip, response tampering)"), T("pwreset-poisoning", "Password-reset host-header poisoning / token flaws"),
        T("remember-me", "Insecure 'remember me' / persistent tokens"), T("oauth-flaws", "OAuth/OIDC misconfig (redirect_uri, state, implicit)"),
        T("jwt-attacks", "JWT: alg=none, weak secret, kid injection, jwk")] },

    // ── Session management ──────────────────────────────────────────────────
    { id: "session", name: "Session management", category: "auth", methods: ["*"],
      refs: ["WSTG-SESS", "PortSwigger: Session"], techniques: [
        T("cookie-flags", "Missing HttpOnly/Secure/SameSite"), T("fixation", "Session fixation / no rotation on login"),
        T("predictable-token", "Predictable/short session tokens"), T("logout-invalidation", "Session not invalidated on logout/timeout")] },

    // ── Access control / authorization ──────────────────────────────────────
    { id: "access-control", name: "Broken access control", category: "access-control", methods: ["*"],
      refs: ["WSTG-ATHZ", "PortSwigger: Access control", "OWASP A01"], techniques: [
        T("idor", "IDOR / horizontal privilege (other users' objects)"), T("vertical-privesc", "Vertical privesc (reach admin functions)"),
        T("forced-browsing", "Forced browsing / unprotected functionality"), T("method-based", "Method-based bypass (GET vs POST, verb tampering)"),
        T("missing-func-authz", "Missing function-level auth (hidden/API routes)"), T("param-based-role", "Parameter-based access control (role in request)")] },
    { id: "api-bola-bfla", name: "API object/function-level auth (BOLA/BFLA)", category: "api", methods: ["*"],
      refs: ["OWASP API1/API5", "PortSwigger: API testing"], techniques: [
        T("bola", "BOLA: object-id tampering across tenants"), T("bfla", "BFLA: privileged function reachable by low-priv"),
        T("mass-assignment", "Mass assignment / excessive property binding"), T("no-object-scoping", "Unscoped list endpoints leak all objects")] },

    // ── Injection ───────────────────────────────────────────────────────────
    { id: "sqli", name: "SQL injection", category: "injection", methods: ["*"],
      refs: ["WSTG-INPV-05", "PortSwigger: SQL injection", "HackTricks: SQLi"], techniques: [
        T("error-based", "Error-based"), T("boolean-blind", "Boolean-based blind"), T("time-blind", "Time-based blind"),
        T("union", "UNION-based extraction"), T("second-order", "Second-order"), T("oob", "Out-of-band (DNS/HTTP)")] },
    { id: "nosqli", name: "NoSQL injection", category: "injection", methods: ["*"],
      refs: ["PortSwigger: NoSQL injection", "HackTricks: NoSQLi"], techniques: [
        T("operator-injection", "Operator injection ($ne/$gt/$where)"), T("syntax-injection", "Syntax injection / auth bypass")] },
    { id: "cmdi", name: "OS command injection", category: "injection", methods: ["*"],
      refs: ["WSTG-INPV-12", "PortSwigger: OS command injection"], techniques: [
        T("inline", "Inline (;|&&|`$()`)"), T("blind-time", "Blind time-delay"), T("blind-oob", "Blind out-of-band")] },
    { id: "xss", name: "Cross-site scripting", category: "client", methods: ["*"],
      refs: ["WSTG-INPV-01/02", "PortSwigger: XSS", "HackTricks: XSS"], techniques: [
        T("reflected", "Reflected"), T("stored", "Stored"), T("dom", "DOM-based"), T("csp-bypass", "CSP bypass / context escape"),
        T("mutation", "mXSS / filter bypass")] },
    { id: "ssti", name: "Server-side template injection", category: "injection", methods: ["*"],
      refs: ["PortSwigger: SSTI", "HackTricks: SSTI"], techniques: [T("detect", "Polyglot detection"), T("rce", "Template → RCE")] },
    { id: "ssrf", name: "Server-side request forgery", category: "injection", methods: ["*"],
      refs: ["WSTG-INPV-19", "PortSwigger: SSRF", "HackTricks: SSRF"], techniques: [
        T("basic", "Basic SSRF (internal/localhost)"), T("cloud-metadata", "Cloud metadata (169.254.169.254)"),
        T("blind-oob", "Blind SSRF (OOB)"), T("filter-bypass", "Filter bypass (redirect/DNS-rebind/encodings)")] },
    { id: "xxe", name: "XML external entity", category: "injection", methods: ["*"],
      refs: ["WSTG-INPV-07", "PortSwigger: XXE"], techniques: [T("file-read", "File read"), T("blind-oob", "Blind/OOB"), T("ssrf", "XXE→SSRF")] },
    { id: "traversal-lfi", name: "Path traversal / LFI / RFI", category: "injection", methods: ["*"],
      refs: ["WSTG-ATHZ-01", "PortSwigger: Path traversal", "HackTricks: LFI"], techniques: [
        T("traversal", "../ traversal + encodings"), T("lfi", "LFI (log poisoning, wrappers)"), T("rfi", "RFI")] },
    { id: "upload", name: "File upload", category: "injection", methods: ["POST", "PUT"],
      refs: ["WSTG-BUSL-09", "PortSwigger: File upload", "HackTricks: file upload"], techniques: [
        T("webshell", "Dangerous type → webshell/RCE"), T("svg-xss", "SVG/HTML XSS"), T("bypass", "Content-type/extension/magic bypass"), T("path", "Filename path traversal")] },
    { id: "injection-misc", name: "Other injection (LDAP/XPath/header/host/SMTP)", category: "injection", methods: ["*"],
      refs: ["WSTG-INPV", "HackTricks"], techniques: [
        T("ldap", "LDAP injection"), T("xpath", "XPath injection"), T("crlf", "CRLF / header injection"),
        T("host-header", "Host-header injection"), T("email", "Email/SMTP header injection")] },

    // ── Client-side / cross-origin ──────────────────────────────────────────
    { id: "csrf", name: "Cross-site request forgery", category: "client", methods: ["POST", "PUT", "DELETE", "PATCH"],
      refs: ["WSTG-SESS-05", "PortSwigger: CSRF"], techniques: [T("no-token", "Missing/!validated CSRF token"), T("samesite", "SameSite bypass"), T("method-override", "Method/CT toggling")] },
    { id: "cors", name: "CORS misconfiguration", category: "client", methods: ["*"],
      refs: ["PortSwigger: CORS", "HackTricks: CORS"], techniques: [T("reflect-origin", "Reflected Origin + credentials"), T("null-origin", "null origin trust"), T("wildcard-creds", "Wildcard + credentials")] },
    { id: "clickjacking", name: "Clickjacking", category: "client", methods: ["GET"],
      refs: ["WSTG-CLNT-09", "PortSwigger: Clickjacking"], techniques: [T("no-frame-defense", "No X-Frame-Options / frame-ancestors")] },
    { id: "open-redirect", name: "Open redirect", category: "client", methods: ["GET", "POST"],
      refs: ["WSTG-CLNT-04", "PortSwigger: OAuth/redirects"], techniques: [T("param-redirect", "Redirect param abuse"), T("filter-bypass", "Filter bypass")] },
    { id: "prototype-pollution", name: "Prototype pollution", category: "client", methods: ["*"],
      refs: ["PortSwigger: Prototype pollution"], techniques: [T("client", "Client-side"), T("server", "Server-side")] },

    // ── Advanced / infra-adjacent ───────────────────────────────────────────
    { id: "deserialization", name: "Insecure deserialization", category: "injection", methods: ["*"],
      refs: ["WSTG-INPV-11", "PortSwigger: Deserialization", "HackTricks"], techniques: [T("php-object", "PHP object injection"), T("java", "Java/ysoserial gadget"), T("dotnet-python", ".NET/Python pickle")] },
    { id: "request-smuggling", name: "HTTP request smuggling", category: "infra", methods: ["*"],
      refs: ["PortSwigger: Request smuggling"], techniques: [T("clte", "CL.TE"), T("tecl", "TE.CL"), T("tete", "TE.TE / obfuscation")] },
    { id: "cache", name: "Web cache poisoning / deception", category: "infra", methods: ["GET"],
      refs: ["PortSwigger: Web cache poisoning/deception"], techniques: [T("poisoning", "Unkeyed-input poisoning"), T("deception", "Path-confusion deception")] },
    { id: "race", name: "Race conditions", category: "logic", methods: ["POST", "PUT", "PATCH"],
      refs: ["PortSwigger: Race conditions"], techniques: [T("limit-overrun", "Limit overrun (single-packet)"), T("toctou", "TOCTOU / multi-endpoint")] },
    { id: "business-logic", name: "Business logic", category: "logic", methods: ["*"],
      refs: ["WSTG-BUSL", "PortSwigger: Business logic"], techniques: [
        T("price-qty", "Price/quantity/negative/overflow tampering"), T("workflow", "Workflow/step-skip abuse"),
        T("coupon-abuse", "Coupon/discount/stacking abuse"), T("payment-state", "Payment-state forgery / mass-assign paid")] },
    { id: "graphql", name: "GraphQL", category: "api", methods: ["POST", "GET"],
      refs: ["PortSwigger: GraphQL", "HackTricks: GraphQL"], techniques: [T("introspection", "Introspection exposure"), T("batching", "Batching/aliasing brute"), T("idor-graphql", "GraphQL IDOR/BOLA")] },
    { id: "websocket", name: "WebSockets", category: "api", methods: ["GET"],
      refs: ["PortSwigger: WebSockets"], techniques: [T("cswsh", "Cross-site WS hijacking"), T("message-injection", "Message tampering/injection")] },
    { id: "rate-limit", name: "Rate limiting / anti-automation", category: "logic", methods: ["*"],
      refs: ["OWASP API4", "WSTG-BUSL"], techniques: [T("no-limit", "No rate limit on sensitive action"), T("enumeration", "Enumeration via unlimited attempts")] },

    // ── Transport / headers / infra ─────────────────────────────────────────
    { id: "sec-headers", name: "Security headers & TLS", category: "infra", methods: ["*"],
      refs: ["WSTG-CONF", "PortSwigger", "Mozilla Observatory"], techniques: [
        T("missing-headers", "Missing HSTS/CSP/XFO/nosniff/Referrer/Permissions"), T("tls-config", "Weak TLS / mixed content")] },
    { id: "vhost-origin", name: "Vhost / origin / WAF bypass", category: "infra", methods: ["*"],
      refs: ["HackTricks: WAF/origin"], techniques: [T("origin-ip", "Direct-to-origin (WAF bypass)"), T("vhost-fuzz", "Vhost/subdomain fuzzing")] },
    { id: "known-cve", name: "Known-vuln / CVE (components)", category: "infra", methods: ["*"],
      refs: ["WSTG-CONF", "OWASP A06", "nuclei/wpscan/Patchstack"], techniques: [T("version-match", "Version → CVE match"), T("template-scan", "nuclei/wpscan template scan")] },
    { id: "xmlrpc-legacy", name: "Legacy/dangerous endpoints", category: "infra", methods: ["*"],
      refs: ["HackTricks", "WSTG-CONF"], techniques: [T("xmlrpc", "xmlrpc pingback/multicall"), T("debug-actuator", "Debug consoles / actuators / admin panels")] },
  ]

  /**
   * Combination-testing metadata layered on top of the declarative CLASSES table.
   * Each entry adds `chainHints`, `wstgId`, and `hacktricksSlug` to the class with
   * the given id — kept in one small table so cross-cutting edits (adding a new
   * chain hint across several classes) are one diff, not fifteen. `all()` and
   * `get()` merge this in transparently.
   */
  const AUGMENT: Record<string, { chainHints?: string[]; wstgId?: string; hacktricksSlug?: string }> = {
    "info-disclosure":  { chainHints: ["user-enum", "sqli", "known-cve"],                       wstgId: "WSTG-INFO",    hacktricksSlug: "info-disclosure" },
    "user-enum":        { chainHints: ["auth", "info-disclosure"],                              wstgId: "WSTG-IDNT-04", hacktricksSlug: "user-enum" },
    "auth":             { chainHints: ["session", "access-control", "user-enum"],               wstgId: "WSTG-ATHN",    hacktricksSlug: "auth" },
    "session":          { chainHints: ["auth", "csrf", "access-control"],                       wstgId: "WSTG-SESS",    hacktricksSlug: "session" },
    "access-control":   { chainHints: ["api-bola-bfla", "auth", "session", "graphql"],          wstgId: "WSTG-ATHZ",    hacktricksSlug: "access-control" },
    "api-bola-bfla":    { chainHints: ["access-control", "graphql", "info-disclosure"],         hacktricksSlug: "api-bola-bfla" },
    "sqli":             { chainHints: ["auth", "info-disclosure", "access-control"],            wstgId: "WSTG-INPV-05", hacktricksSlug: "sqli" },
    "nosqli":           { chainHints: ["auth", "access-control"],                                                       hacktricksSlug: "nosqli" },
    "cmdi":             { chainHints: ["upload", "traversal-lfi", "ssti", "deserialization"],   wstgId: "WSTG-INPV-12", hacktricksSlug: "cmdi" },
    "xss":              { chainHints: ["csrf", "cors", "session", "prototype-pollution"],       wstgId: "WSTG-INPV-01", hacktricksSlug: "xss" },
    "ssti":             { chainHints: ["cmdi", "xss"],                                                                  hacktricksSlug: "ssti" },
    "ssrf":             { chainHints: ["api-bola-bfla", "info-disclosure", "xxe"],              wstgId: "WSTG-INPV-19", hacktricksSlug: "ssrf" },
    "xxe":              { chainHints: ["ssrf", "traversal-lfi", "info-disclosure"],             wstgId: "WSTG-INPV-07", hacktricksSlug: "xxe" },
    "traversal-lfi":    { chainHints: ["cmdi", "info-disclosure"],                              wstgId: "WSTG-ATHZ-01", hacktricksSlug: "traversal-lfi" },
    "upload":           { chainHints: ["cmdi", "xss", "traversal-lfi"],                         wstgId: "WSTG-BUSL-09", hacktricksSlug: "upload" },
    "injection-misc":   { chainHints: ["cmdi", "auth"],                                         wstgId: "WSTG-INPV",    hacktricksSlug: "injection-misc" },
    "csrf":             { chainHints: ["session", "xss", "access-control"],                     wstgId: "WSTG-SESS-05", hacktricksSlug: "csrf" },
    "cors":             { chainHints: ["xss", "csrf", "info-disclosure"],                                               hacktricksSlug: "cors" },
    "clickjacking":     { chainHints: ["csrf"],                                                 wstgId: "WSTG-CLNT-09", hacktricksSlug: "clickjacking" },
    "open-redirect":    { chainHints: ["xss", "auth", "cors"],                                  wstgId: "WSTG-CLNT-04", hacktricksSlug: "open-redirect" },
    "prototype-pollution": { chainHints: ["xss", "deserialization", "cmdi"],                                            hacktricksSlug: "prototype-pollution" },
    "deserialization":  { chainHints: ["cmdi", "ssti"],                                         wstgId: "WSTG-INPV-11", hacktricksSlug: "deserialization" },
    "request-smuggling": { chainHints: ["cache", "sec-headers"],                                                        hacktricksSlug: "request-smuggling" },
    "cache":            { chainHints: ["request-smuggling", "xss"],                                                     hacktricksSlug: "cache" },
    "race":             { chainHints: ["business-logic", "access-control"],                                             hacktricksSlug: "race" },
    "business-logic":   { chainHints: ["race", "rate-limit", "access-control"],                 wstgId: "WSTG-BUSL",    hacktricksSlug: "business-logic" },
    "graphql":          { chainHints: ["access-control", "api-bola-bfla", "info-disclosure"],                           hacktricksSlug: "graphql" },
    "websocket":        { chainHints: ["auth", "csrf"],                                                                 hacktricksSlug: "websocket" },
    "rate-limit":       { chainHints: ["business-logic", "user-enum", "auth"],                                          hacktricksSlug: "rate-limit" },
    "sec-headers":      { chainHints: ["clickjacking", "xss", "cors"],                          wstgId: "WSTG-CONF",    hacktricksSlug: "sec-headers" },
    "vhost-origin":     { chainHints: ["known-cve", "info-disclosure"],                                                 hacktricksSlug: "vhost-origin" },
    "known-cve":        { chainHints: ["cmdi", "deserialization", "sqli"],                      wstgId: "WSTG-CONF",    hacktricksSlug: "known-cve" },
    "xmlrpc-legacy":    { chainHints: ["cmdi", "known-cve"],                                    wstgId: "WSTG-CONF",    hacktricksSlug: "xmlrpc-legacy" },
  }

  function augment(c: VulnClass): VulnClass {
    const extra = AUGMENT[c.id]
    if (!extra) return c
    // Merge — never overwrite an existing declarative field on VulnClass.
    return { ...c, ...extra, chainHints: c.chainHints ?? extra.chainHints, wstgId: c.wstgId ?? extra.wstgId, hacktricksSlug: c.hacktricksSlug ?? extra.hacktricksSlug }
  }

  export function all(): VulnClass[] {
    return CLASSES.map(augment)
  }
  export function get(id: string): VulnClass | undefined {
    const c = CLASSES.find((c) => c.id === id)
    return c ? augment(c) : undefined
  }
  export function byCategory(cat: Category): VulnClass[] {
    return CLASSES.filter((c) => c.category === cat).map(augment)
  }
  export function ids(): string[] {
    return CLASSES.map((c) => c.id)
  }
  /** Total technique count across all classes — the theoretical per-endpoint ceiling. */
  export function techniqueCount(): number {
    return CLASSES.reduce((n, c) => n + c.techniques.length, 0)
  }
  /** Classes worth testing on a given HTTP method. */
  export function forMethod(method: string): VulnClass[] {
    const m = method.toUpperCase()
    return CLASSES.filter((c) => c.methods.includes("*") || c.methods.includes(m)).map(augment)
  }
}
