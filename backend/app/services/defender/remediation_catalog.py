"""
Remediation Playbook Catalog for CyberSentinal Defender Agent.
Contains technical root causes, specific actionable fixes, implementation steps,
server configuration snippets, effort estimates, and verification procedures.
"""

from typing import Dict, Any, Optional

REMEDIATION_CATALOG: Dict[str, Dict[str, Any]] = {
    "VULN-TLS-NO-HTTPS": {
        "root_cause": "The web application accepts unencrypted HTTP traffic without enforcing transport encryption (TLS) or automatic HTTPS redirection.",
        "actionable_fix": "Deploy an authenticated TLS certificate, configure automated HTTP-to-HTTPS (port 80 to 443) 301 redirection, and activate HSTS.",
        "implementation_steps": [
            "1. Obtain a valid TLS certificate via Let's Encrypt Certbot, AWS Certificate Manager, or enterprise CA.",
            "2. Configure web server reverse proxy to listen on port 443 with TLS 1.2+ and strong cipher suites.",
            "3. Add unconditional permanent redirection (HTTP 301) for all incoming port 80 requests to https://.",
            "4. Verify that internal hyperlinks and asset URLs use relative paths or HTTPS schemes.",
        ],
        "code_snippets": {
            "Nginx": (
                "server {\n"
                "    listen 80;\n"
                "    server_name example.com www.example.com;\n"
                "    return 301 https://$host$request_uri;\n"
                "}\n"
                "server {\n"
                "    listen 443 ssl http2;\n"
                "    server_name example.com;\n"
                "    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;\n"
                "    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;\n"
                "    ssl_protocols TLSv1.2 TLSv1.3;\n"
                "}"
            ),
            "Apache": (
                "<VirtualHost *:80>\n"
                "    ServerName example.com\n"
                "    RewriteEngine On\n"
                "    RewriteCond %{HTTPS} off\n"
                "    RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n"
                "</VirtualHost>"
            ),
            "Cloudflare / Edge": "Enable 'Always Use HTTPS' and 'Automatic HTTPS Rewrites' in SSL/TLS edge settings.",
        },
        "effort_hours": 4.0,
        "service_cost": 0.0,
        "dependencies": ["DNS ownership verification", "Reverse proxy root access"],
        "assumptions": ["Domain ownership confirmed", "Automated renewal mechanism supported"],
        "verification_procedure": "curl -I -s http://<TARGET_HOST> | grep -E -i 'HTTP/|location:' (Verify 301 redirect to https://)",
    },
    "VULN-TLS-MISSING-HSTS": {
        "root_cause": "The web server serves HTTPS responses without the Strict-Transport-Security header, leaving users vulnerable to SSL stripping attacks on subsequent visits.",
        "actionable_fix": "Add the Strict-Transport-Security header with a minimum one-year duration (31536000 seconds), includeSubDomains, and preload directives.",
        "implementation_steps": [
            "1. Confirm all subdomains support HTTPS to prevent accidental outages when includeSubDomains is activated.",
            "2. Add the Strict-Transport-Security response header to web server configuration.",
            "3. Reload web server configuration without downtime.",
            "4. (Optional) Submit domain to the Chromium HSTS Preload list (hstspreload.org).",
        ],
        "code_snippets": {
            "Nginx": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
            "Apache": 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
            "Next.js": (
                "// next.config.ts / next.config.js\n"
                "headers: async () => [{\n"
                "  source: '/(.*)',\n"
                "  headers: [{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' }]\n"
                "}]"
            ),
            "Express": (
                "const helmet = require('helmet');\n"
                "app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));"
            ),
        },
        "effort_hours": 2.0,
        "service_cost": 0.0,
        "dependencies": ["Active HTTPS certificate"],
        "assumptions": ["All critical subdomains support HTTPS"],
        "verification_procedure": "curl -sI https://<TARGET_HOST> | grep -i strict-transport-security",
    },
    "VULN-SEC-HDR-NO-CSP": {
        "root_cause": "The application lacks a Content-Security-Policy (CSP) header, allowing unrestricted execution of inline scripts and unauthorized resource loading.",
        "actionable_fix": "Define and enforce a restrictive Content-Security-Policy that whitelists only trusted script, style, and object origins.",
        "implementation_steps": [
            "1. Audit third-party dependencies, analytics trackers, and external scripts loaded by the application.",
            "2. Deploy initial policy in Report-Only mode ('Content-Security-Policy-Report-Only') to identify legitimate violations.",
            "3. Refactor inline <script> blocks to use cryptographically random nonces or hashes.",
            "4. Switch header from Report-Only to active enforcement mode ('Content-Security-Policy').",
        ],
        "code_snippets": {
            "Nginx": (
                "add_header Content-Security-Policy \""
                "default-src 'self'; "
                "script-src 'self' 'nonce-$request_id'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "form-action 'self'; "
                "frame-ancestors 'self';\" always;"
            ),
            "Express": (
                "const helmet = require('helmet');\n"
                "app.use(helmet.contentSecurityPolicy({\n"
                "  directives: {\n"
                "    defaultSrc: [\"'self'\"],\n"
                "    scriptSrc: [\"'self'\"],\n"
                "    objectSrc: [\"'none'\"],\n"
                "    upgradeInsecureRequests: [],\n"
                "  },\n"
                "}));"
            ),
            "Next.js": (
                "// Set CSP via middleware.ts with dynamic nonce\n"
                "const cspHeader = `default-src 'self'; script-src 'self' 'nonce-${nonce}'; object-src 'none';`;\n"
                "response.headers.set('Content-Security-Policy', cspHeader);"
            ),
        },
        "effort_hours": 6.0,
        "service_cost": 0.0,
        "dependencies": ["Asset dependency audit completed"],
        "assumptions": ["Inline scripts can be refactored to nonces or external files"],
        "verification_procedure": "curl -sI https://<TARGET_HOST> | grep -i content-security-policy",
    },
    "VULN-SEC-HDR-NO-XFO": {
        "root_cause": "The web application does not specify X-Frame-Options or CSP frame-ancestors, permitting third-party sites to render it inside hidden iframes.",
        "actionable_fix": "Configure 'X-Frame-Options: SAMEORIGIN' (or 'DENY') and declare CSP 'frame-ancestors 'self''.",
        "implementation_steps": [
            "1. Determine whether the site requires legitimate iframe embedding by partner domains.",
            "2. If embedding is never permitted, configure X-Frame-Options: DENY.",
            "3. If only same-origin framing is required, configure X-Frame-Options: SAMEORIGIN.",
            "4. Add complementary CSP 'frame-ancestors 'self'' directive.",
        ],
        "code_snippets": {
            "Nginx": (
                "add_header X-Frame-Options \"SAMEORIGIN\" always;\n"
                "add_header Content-Security-Policy \"frame-ancestors 'self';\" always;"
            ),
            "Apache": 'Header always set X-Frame-Options "SAMEORIGIN"',
            "Next.js": (
                "headers: async () => [{\n"
                "  source: '/(.*)',\n"
                "  headers: [{ key: 'X-Frame-Options', value: 'SAMEORIGIN' }]\n"
                "}]"
            ),
            "Express": "app.use(helmet.frameguard({ action: 'sameorigin' }));",
        },
        "effort_hours": 2.0,
        "service_cost": 0.0,
        "dependencies": [],
        "assumptions": ["Third-party framing is not a core business requirement"],
        "verification_procedure": "curl -sI https://<TARGET_HOST> | grep -E -i 'x-frame-options|frame-ancestors'",
    },
    "VULN-SEC-HDR-NO-NOSNIFF": {
        "root_cause": "The server omits the X-Content-Type-Options: nosniff header, allowing web browsers to override declared MIME types and execute uploaded files as script.",
        "actionable_fix": "Add 'X-Content-Type-Options: nosniff' header across all HTTP responses.",
        "implementation_steps": [
            "1. Ensure all served static assets (CSS, JS, images, fonts) include accurate Content-Type response headers.",
            "2. Add 'X-Content-Type-Options: nosniff' to web server configuration.",
            "3. Validate that CSS and script bundles load without MIME type errors.",
        ],
        "code_snippets": {
            "Nginx": 'add_header X-Content-Type-Options "nosniff" always;',
            "Apache": 'Header always set X-Content-Type-Options "nosniff"',
            "Express": "app.use(helmet.noSniff());",
        },
        "effort_hours": 1.0,
        "service_cost": 0.0,
        "dependencies": [],
        "assumptions": ["Server serves accurate Content-Type headers"],
        "verification_procedure": "curl -sI https://<TARGET_HOST> | grep -i x-content-type-options",
    },
    "VULN-SEC-HDR-NO-REFERRER": {
        "root_cause": "The application lacks an explicit Referrer-Policy header, causing browsers to send full URLs including internal query parameters in Referer headers.",
        "actionable_fix": "Set 'Referrer-Policy: strict-origin-when-cross-origin' to protect sensitive URL tokens from leaking to external domains.",
        "implementation_steps": [
            "1. Add 'Referrer-Policy: strict-origin-when-cross-origin' to server or CDN response headers.",
            "2. Verify external links preserve origin privacy while maintaining internal navigation context.",
        ],
        "code_snippets": {
            "Nginx": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            "Apache": 'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
            "Express": "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));",
        },
        "effort_hours": 1.0,
        "service_cost": 0.0,
        "dependencies": [],
        "assumptions": ["Third-party analytics does not strictly require path referrers"],
        "verification_procedure": "curl -sI https://<TARGET_HOST> | grep -i referrer-policy",
    },
    "VULN-SEC-HDR-NO-PERMISSIONS": {
        "root_cause": "The application lacks a Permissions-Policy header, leaving browser hardware APIs (camera, microphone, geolocation) accessible to embedded iframes and third-party scripts.",
        "actionable_fix": "Add 'Permissions-Policy' to explicitly disable unnecessary hardware interfaces.",
        "implementation_steps": [
            "1. Review whether the application uses camera, microphone, or geolocation APIs.",
            "2. Add 'Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()' to web server response headers.",
        ],
        "code_snippets": {
            "Nginx": 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;',
            "Apache": 'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()"',
            "Express": "app.use((req, res, next) => { res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()'); next(); });",
        },
        "effort_hours": 1.5,
        "service_cost": 0.0,
        "dependencies": [],
        "assumptions": ["Application does not rely on unrestricted camera/microphone"],
        "verification_procedure": "curl -sI https://<TARGET_HOST> | grep -i permissions-policy",
    },
    "VULN-CORS-WILDCARD-CREDENTIALS": {
        "root_cause": "CORS configuration inadvertently pairs Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true, violating security boundaries.",
        "actionable_fix": "Remove the wildcard origin. Dynamically validate incoming Origin headers against an explicit, trusted domain whitelist.",
        "implementation_steps": [
            "1. Audit client consumer domains that require cross-origin API access.",
            "2. Replace wildcard '*' with explicit origin validation logic in API middleware.",
            "3. Reject untrusted origins by returning no Access-Control-Allow-Origin header.",
        ],
        "code_snippets": {
            "Express": (
                "const cors = require('cors');\n"
                "const allowed = ['https://app.example.com', 'https://admin.example.com'];\n"
                "app.use(cors({\n"
                "  origin: (origin, callback) => {\n"
                "    if (!origin || allowed.indexOf(origin) !== -1) callback(null, true);\n"
                "    else callback(new Error('Disallowed by CORS policy'));\n"
                "  },\n"
                "  credentials: true,\n"
                "}));"
            ),
            "FastAPI": (
                "app.add_middleware(\n"
                "    CORSMiddleware,\n"
                "    allow_origins=['https://app.example.com'],\n"
                "    allow_credentials=True,\n"
                "    allow_methods=['GET', 'POST', 'PUT', 'DELETE'],\n"
                "    allow_headers=['*'],\n"
                ")"
            ),
        },
        "effort_hours": 4.0,
        "service_cost": 0.0,
        "dependencies": ["Cross-origin consumer domain inventory"],
        "assumptions": ["All trusted origins use HTTPS"],
        "verification_procedure": "curl -H 'Origin: https://malicious.com' -I https://<TARGET_HOST>/api/... (verify no Allow-Origin reflected)",
    },
    "VULN-COOKIE-NO-SECURE": {
        "root_cause": "Session or sensitive cookies are issued without the 'Secure' attribute, allowing browsers to send them in cleartext over unencrypted HTTP requests.",
        "actionable_fix": "Configure the web framework session manager and cookie generators to append '; Secure' to all Set-Cookie directives.",
        "implementation_steps": [
            "1. Locate cookie generation in backend session middleware or authentication controllers.",
            "2. Set the cookie 'secure: true' property.",
            "3. In development environments using localhost HTTP, make the Secure flag conditionally disabled only if NODE_ENV === 'development'.",
        ],
        "code_snippets": {
            "Express": (
                "app.use(session({\n"
                "  cookie: { secure: true, httpOnly: true, sameSite: 'lax' }\n"
                "}));"
            ),
            "Django": "SESSION_COOKIE_SECURE = True\nCSRF_COOKIE_SECURE = True",
            "PHP": "session_set_cookie_params(['secure' => true, 'httponly' => true, 'samesite' => 'Lax']);",
        },
        "effort_hours": 2.0,
        "service_cost": 0.0,
        "dependencies": ["Application running behind valid HTTPS"],
        "assumptions": ["Production environment operates over HTTPS"],
        "verification_procedure": "curl -sI https://<TARGET_HOST> | grep -i set-cookie (verify '; Secure' is present)",
    },
    "VULN-COOKIE-NO-HTTPONLY": {
        "root_cause": "Session authentication cookies lack the HttpOnly flag, allowing browser JavaScript (document.cookie) to read them and magnifying XSS impact.",
        "actionable_fix": "Enforce the 'HttpOnly' attribute on all session identifiers and authorization tokens.",
        "implementation_steps": [
            "1. Inspect all cookies issued via Set-Cookie headers.",
            "2. Identify session IDs, refresh tokens, and CSRF cookies.",
            "3. Set 'httpOnly: true' on all session and auth cookies in server configuration.",
        ],
        "code_snippets": {
            "Express": "res.cookie('session_token', token, { httpOnly: true, secure: true, sameSite: 'strict' });",
            "Django": "SESSION_COOKIE_HTTPONLY = True",
            "FastAPI": "response.set_cookie(key='session', value=token, httponly=True, secure=True, samesite='lax')",
        },
        "effort_hours": 2.0,
        "service_cost": 0.0,
        "dependencies": [],
        "assumptions": ["Client-side JavaScript does not legitimately need to read raw session tokens"],
        "verification_procedure": "curl -sI https://<TARGET_HOST> | grep -i set-cookie (verify '; HttpOnly' is present)",
    },
    "VULN-INFO-SERVER-VERSION": {
        "root_cause": "The web server emits detailed product name and version numbers in the 'Server' HTTP response banner.",
        "actionable_fix": "Configure web server directives to suppress granular version banners or completely mask the Server header.",
        "implementation_steps": [
            "1. Open web server main configuration (nginx.conf or httpd.conf).",
            "2. Set ServerTokens to Prod (Apache) or server_tokens off (Nginx).",
            "3. Test configuration syntax and reload web server service.",
        ],
        "code_snippets": {
            "Nginx": "http {\n    server_tokens off;\n}",
            "Apache": "ServerTokens Prod\nServerSignature Off",
        },
        "effort_hours": 1.5,
        "service_cost": 0.0,
        "dependencies": ["Web server configuration access"],
        "assumptions": ["Server reload will not disrupt active traffic"],
        "verification_procedure": "curl -sI https://<TARGET_HOST> | grep -i server (verify version number is absent)",
    },
    "VULN-INFO-X-POWERED-BY": {
        "root_cause": "The backend framework advertises its technology stack in the X-Powered-By response header.",
        "actionable_fix": "Disable the X-Powered-By header in application code or reverse proxy settings.",
        "implementation_steps": [
            "1. Locate framework initialization code.",
            "2. Disable the default X-Powered-By header.",
            "3. Alternatively, strip the header at the Nginx / Cloudflare reverse proxy tier.",
        ],
        "code_snippets": {
            "Express": "app.disable('x-powered-by');",
            "Next.js": "// next.config.ts\npoweredByHeader: false,",
            "PHP": "; php.ini\nexpose_php = Off",
            "Nginx": "proxy_hide_header X-Powered-By;",
        },
        "effort_hours": 1.0,
        "service_cost": 0.0,
        "dependencies": [],
        "assumptions": ["Framework configuration reload permitted"],
        "verification_procedure": "curl -sI https://<TARGET_HOST> | grep -i x-powered-by (verify header is absent)",
    },
    "VULN-INFO-ROBOTS-SENSITIVE-PATHS": {
        "root_cause": "The robots.txt file advertises sensitive administrative and private directories to search crawlers and threat actors.",
        "actionable_fix": "Remove sensitive path names from robots.txt. Enforce robust authentication, authorization checks, and IP ACLs on private routes.",
        "implementation_steps": [
            "1. Review all 'Disallow:' directives in robots.txt.",
            "2. Remove references to /admin, /private, /backup, and internal APIs.",
            "3. Rely on HTTP 401/403 access control and <meta name='robots' content='noindex'> rather than robots.txt secrecy.",
        ],
        "code_snippets": {
            "Robots.txt": (
                "# Clean, minimal robots.txt\n"
                "User-agent: *\n"
                "Disallow:\n"
                "Sitemap: https://example.com/sitemap.xml"
            ),
        },
        "effort_hours": 1.5,
        "service_cost": 0.0,
        "dependencies": [],
        "assumptions": ["Endpoints are protected by proper authentication logic"],
        "verification_procedure": "curl -s https://<TARGET_HOST>/robots.txt (verify sensitive paths removed)",
    },
    "VULN-BEST-PRACTICE-NO-SECURITY-TXT": {
        "root_cause": "The organization does not publish an RFC 9116 security.txt contact file, making responsible vulnerability disclosure difficult for researchers.",
        "actionable_fix": "Publish a cryptographically verified or signed RFC 9116 security.txt file at /.well-known/security.txt.",
        "implementation_steps": [
            "1. Create a security contact mailbox (e.g. security@example.com).",
            "2. Draft /.well-known/security.txt with Contact, Expires, and Preferred-Languages fields.",
            "3. Deploy file to public web root with Content-Type: text/plain.",
        ],
        "code_snippets": {
            "security.txt": (
                "Contact: mailto:security@example.com\n"
                "Expires: 2027-12-31T23:59:59.000Z\n"
                "Preferred-Languages: en\n"
                "Canonical: https://example.com/.well-known/security.txt\n"
                "Policy: https://example.com/security-policy"
            ),
        },
        "effort_hours": 1.0,
        "service_cost": 0.0,
        "dependencies": ["Designated security contact email"],
        "assumptions": ["Security mailbox is monitored by team"],
        "verification_procedure": "curl -s https://<TARGET_HOST>/.well-known/security.txt | grep -i contact",
    },
}


def get_playbook_for_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    finding_id = finding.get("id", "")

    # Exact match
    if finding_id in REMEDIATION_CATALOG:
        return REMEDIATION_CATALOG[finding_id]

    # Partial prefix match (e.g. cookies)
    for prefix, playbook in REMEDIATION_CATALOG.items():
        if finding_id.startswith(prefix.replace("*", "")):
            return playbook

    # Handle CVEs
    cve_id = finding.get("cve_id")
    if cve_id or "CVE-" in finding_id:
        cve_name = cve_id or finding_id.replace("VULN-", "")
        return {
            "root_cause": f"Disclosed component matches published {cve_name} with known security advisories.",
            "actionable_fix": finding.get(
                "remediation",
                f"Immediately upgrade affected component to latest vendor patch release addressing {cve_name}."
            ),
            "implementation_steps": [
                f"1. Review vendor security advisory for {cve_name}.",
                "2. Apply official upstream patch or upgrade to non-vulnerable component version in staging.",
                "3. Execute regression tests to ensure application compatibility.",
                "4. Deploy updated component to production and re-verify banner suppression.",
            ],
            "code_snippets": {
                "Package Manager": f"# Update affected packages\napt update && apt --only-upgrade install <PACKAGE_NAME>\n# or\nyum update <PACKAGE_NAME>",
            },
            "effort_hours": 8.0,
            "service_cost": 0.0,
            "dependencies": ["Staging environment verification", "Vendor patch availability"],
            "assumptions": ["Vendor has published an official patch"],
            "verification_procedure": "curl -sI https://<TARGET_HOST> | grep -i server (verify patched version)",
        }

    # Fallback for generic findings
    return {
        "root_cause": finding.get("potential_impact", "Configuration or design weakness observed in active web service."),
        "actionable_fix": finding.get("remediation", "Apply vendor security best practices and harden web server configuration."),
        "implementation_steps": [
            "1. Review observed evidence and identify affected component.",
            "2. Update server or framework configuration according to OWASP guidelines.",
            "3. Test in staging environment before applying to production.",
        ],
        "code_snippets": {},
        "effort_hours": 2.5,
        "service_cost": 0.0,
        "dependencies": [],
        "assumptions": ["Standard engineering workflow applied"],
        "verification_procedure": f"curl -sI {finding.get('affected_url_or_component', 'target')}",
    }
