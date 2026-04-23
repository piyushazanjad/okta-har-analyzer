import { inflateRawSync } from 'zlib';

// ─── Endpoint Knowledge Base ───────────────────────────────────────────────
const ENDPOINT_MAP = [
  {
    pattern: /\/oauth2\/[^/?]+\/v1\/authorize|\/oauth2\/v1\/authorize/,
    name: 'Authorization Request',
    description: 'Browser navigates to Okta to begin authentication',
    phase: 'authorization', from: 'browser', to: 'okta',
  },
  {
    pattern: /\/login\/login\.htm/,
    name: 'Login Page',
    description: 'Okta serves the login form to the browser',
    phase: 'authentication', from: 'browser', to: 'okta',
  },
  {
    pattern: /\/api\/v1\/authn/,
    name: 'Primary Authentication',
    description: 'Credentials submitted to Okta for validation',
    phase: 'authentication', from: 'browser', to: 'okta',
  },
  {
    pattern: /\/idp\/idx/,
    name: 'Identity Engine (IDX)',
    description: 'Okta Identity Engine interaction step',
    phase: 'authentication', from: 'browser', to: 'okta',
  },
  {
    pattern: /\/login\/token\/redirect/,
    name: 'Session Token Redirect',
    description: 'Auth complete — establishing browser session',
    phase: 'session', from: 'okta', to: 'browser',
  },
  {
    pattern: /\/login\/sessionCookieRedirect/,
    name: 'Session Cookie Redirect',
    description: 'Session cookie being set in the browser',
    phase: 'session', from: 'okta', to: 'browser',
  },
  {
    pattern: /\/oauth2\/[^/?]+\/v1\/token|\/oauth2\/v1\/token/,
    name: 'Token Exchange',
    description: 'Authorization code exchanged for access/ID tokens',
    phase: 'token', from: 'app', to: 'okta',
  },
  {
    pattern: /\/oauth2\/[^/?]+\/v1\/userinfo|\/oauth2\/v1\/userinfo/,
    name: 'UserInfo Request',
    description: 'User profile fetched using access token',
    phase: 'token', from: 'app', to: 'okta',
  },
  {
    pattern: /\/oauth2\/[^/?]+\/v1\/keys|\/oauth2\/v1\/keys/,
    name: 'JWKS Fetch',
    description: 'Public keys fetched for JWT signature verification',
    phase: 'token', from: 'app', to: 'okta',
  },
  {
    pattern: /\/oauth2\/[^/?]+\/v1\/introspect|\/oauth2\/v1\/introspect/,
    name: 'Token Introspection',
    description: 'Token validity checked at introspection endpoint',
    phase: 'token', from: 'app', to: 'okta',
  },
  {
    pattern: /\/oauth2\/[^/?]+\/v1\/revoke|\/oauth2\/v1\/revoke/,
    name: 'Token Revocation',
    description: 'Token revoked at Okta',
    phase: 'token', from: 'app', to: 'okta',
  },
  {
    pattern: /\/app\/[^/?]+\/[^/?]+\/sso\/saml/,
    name: 'SAML SSO Initiation',
    description: 'SAML authentication request received by Okta',
    phase: 'saml', from: 'browser', to: 'okta',
  },
  {
    pattern: /\/idp\/sso/,
    name: 'IdP SSO Endpoint',
    description: 'Okta acting as Identity Provider for SAML flow',
    phase: 'saml', from: 'browser', to: 'okta',
  },
  {
    pattern: /\/well-known\/openid-configuration/,
    name: 'OIDC Discovery',
    description: 'OpenID Connect discovery document fetched',
    phase: 'discovery', from: 'app', to: 'okta',
  },
  {
    pattern: /\/api\/v1\/sessions/,
    name: 'Session Check',
    description: 'Okta session validity checked',
    phase: 'session', from: 'browser', to: 'okta',
  },
  {
    pattern: /\/oauth2\/[^/?]+\/v1\/device\/authorize|\/v1\/device\/authorize/,
    name: 'Device Authorization',
    description: 'Device authorization request initiated',
    phase: 'authorization', from: 'app', to: 'okta',
  },
];

// ─── Artifact Extraction ───────────────────────────────────────────────────
function decodeJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf-8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf-8'));
    return { header, payload, raw: token };
  } catch { return null; }
}

function findJWTs(text) {
  if (!text) return [];
  const jwtRegex = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
  const matches = [...new Set(text.match(jwtRegex) || [])];
  return matches
    .map(raw => decodeJWT(raw))
    .filter(Boolean)
    .slice(0, 5);
}

function extractSAML(text) {
  if (!text) return null;
  const responseMatch = text.match(/SAMLResponse=([^&\s"'<>]+)/);
  const requestMatch = text.match(/SAMLRequest=([^&\s"'<>]+)/);
  const match = responseMatch || requestMatch;
  if (!match) return null;

  try {
    const encoded = decodeURIComponent(match[1]);
    const buffer = Buffer.from(encoded, 'base64');
    let xml;
    if (requestMatch) {
      try { xml = inflateRawSync(buffer).toString('utf-8'); }
      catch { xml = buffer.toString('utf-8'); }
    } else {
      xml = buffer.toString('utf-8');
    }

    const issuer = xml.match(/<(?:saml:|saml2:)?Issuer[^>]*>([^<]+)<\/(?:saml:|saml2:)?Issuer>/)?.[1]?.trim();
    const status = xml.match(/StatusCode[^>]+Value="[^"]*:([^"]+)"/)?.[1]?.trim();
    const nameID = xml.match(/<(?:saml:|saml2:)?NameID[^>]*>([^<]+)<\/(?:saml:|saml2:)?NameID>/)?.[1]?.trim();
    const destination = xml.match(/Destination="([^"]+)"/)?.[1]?.trim();
    const conditions = xml.match(/NotBefore="([^"]+)"/)?.[1];
    const notOnOrAfter = xml.match(/NotOnOrAfter="([^"]+)"/)?.[1];

    // Extract attributes
    const attributes = {};
    const attrRegex = /<(?:saml:|saml2:)?Attribute\s+Name="([^"]+)"[^>]*>[\s\S]*?<(?:saml:|saml2:)?AttributeValue[^>]*>([^<]+)<\/(?:saml:|saml2:)?AttributeValue>/g;
    let attrMatch;
    while ((attrMatch = attrRegex.exec(xml)) !== null) {
      attributes[attrMatch[1]] = attrMatch[2].trim();
    }

    return {
      type: requestMatch ? 'SAMLRequest' : 'SAMLResponse',
      issuer, status, nameID, destination,
      notBefore: conditions,
      notOnOrAfter,
      attributes: Object.keys(attributes).length > 0 ? attributes : null,
      xmlPreview: xml.substring(0, 800),
      fullXmlLength: xml.length,
    };
  } catch { return null; }
}

function extractErrorFromResponse(entry) {
  if (!entry.response || entry.response.status < 400) return null;
  const text = entry.response.content?.text || '';
  if (!text) return { status: entry.response.status };
  try {
    const parsed = JSON.parse(text);
    return {
      status: entry.response.status,
      errorCode: parsed.errorCode || parsed.error,
      errorSummary: parsed.errorSummary || parsed.error_description,
      errorId: parsed.errorId,
      errorCauses: parsed.errorCauses?.map(c => c.errorSummary),
    };
  } catch {
    return { status: entry.response.status, raw: text.substring(0, 300) };
  }
}

// ─── URL / Domain Helpers ──────────────────────────────────────────────────
function isOktaDomain(url) {
  return /\.okta\.com|\.okta-emea\.com|\.oktapreview\.com|\.okta-gov\.com/.test(url);
}

function isOktaAuthPath(url) {
  try {
    const { pathname } = new URL(url);
    return /^\/(oauth2|idp|login|app)\//i.test(pathname);
  } catch { return false; }
}

function isCallbackEntry(entry) {
  const url = entry.request.url;
  const body = entry.request.postData?.text || '';
  return /[?&]code=[^&]+|SAMLResponse=|[?&]id_token=|[?&]error=/.test(url + body);
}

function matchEndpoint(url) {
  try {
    const { pathname } = new URL(url);
    return ENDPOINT_MAP.find(ep => ep.pattern.test(pathname)) || null;
  } catch { return null; }
}

// ─── Protocol Detection ────────────────────────────────────────────────────
function detectProtocol(entries) {
  const allText = entries.map(e => [
    e.request.url,
    e.request.postData?.text || '',
  ].join('\n')).join('\n');

  if (/SAMLRequest|SAMLResponse/.test(allText)) {
    return /SAMLRequest/.test(allText) ? 'SAML (SP-Initiated)' : 'SAML (IdP-Initiated)';
  }
  if (/\/idp\/idx/.test(allText)) return 'OIDC + Okta Identity Engine';
  if (/code_challenge/.test(allText)) return 'OIDC Authorization Code + PKCE';
  if (/grant_type=client_credentials/.test(allText)) return 'OAuth 2.0 Client Credentials';
  if (/device\/authorize|device_code/.test(allText)) return 'OAuth 2.0 Device Authorization';
  if (/response_type=token/.test(allText)) return 'OAuth 2.0 Implicit (Legacy)';
  if (/\/oauth2\//.test(allText)) return 'OIDC Authorization Code';
  return 'Unknown';
}

// ─── Key Params to Surface ────────────────────────────────────────────────
const SURFACE_PARAMS = new Set([
  'scope', 'response_type', 'grant_type', 'client_id', 'redirect_uri',
  'code_challenge_method', 'nonce', 'prompt', 'state', 'error',
  'error_description', 'code', 'idp', 'acr_values', 'max_age',
  'response_mode', 'login_hint', 'iss', 'issuer',
]);

function extractKeyParams(url, postBody) {
  const params = {};
  try {
    const u = new URL(url);
    for (const [k, v] of u.searchParams.entries()) {
      if (SURFACE_PARAMS.has(k)) {
        params[k] = k === 'SAMLRequest' ? '[encoded]' : v;
      }
    }
  } catch {}
  if (postBody) {
    try {
      const p = new URLSearchParams(postBody);
      for (const [k, v] of p.entries()) {
        if (SURFACE_PARAMS.has(k)) params[k] = v;
      }
    } catch {}
  }
  return Object.keys(params).length ? params : null;
}

// ─── Raw Request / Response Extraction ───────────────────────────────────
const KEEP_REQ_HEADERS = new Set([
  'authorization', 'content-type', 'content-length', 'accept', 'origin',
  'referer', 'x-okta-user-agent-extended', 'x-forwarded-for',
  'x-device-fingerprint', 'x-request-id',
]);
const KEEP_RES_HEADERS = new Set([
  'location', 'content-type', 'content-length', 'x-okta-request-id',
  'x-rate-limit-limit', 'x-rate-limit-remaining', 'x-rate-limit-reset',
  'cache-control', 'www-authenticate', 'x-content-type-options',
]);

function filterHeaders(headers = [], keepSet) {
  return headers
    .filter(h => keepSet.has(h.name.toLowerCase()))
    .map(h => ({ name: h.name, value: h.value }));
}

function formatBody(text, mimeType = '') {
  if (!text) return null;
  const mime = mimeType.toLowerCase();
  if (mime.includes('html')) return { type: 'html', display: '[HTML — login/redirect page, not shown]' };
  if (mime.includes('json') || text.trimStart().startsWith('{') || text.trimStart().startsWith('[')) {
    try {
      return { type: 'json', display: JSON.stringify(JSON.parse(text), null, 2) };
    } catch {}
  }
  if (mime.includes('x-www-form-urlencoded')) {
    try {
      const pairs = [...new URLSearchParams(text).entries()];
      return { type: 'form', display: pairs.map(([k, v]) => `${k} = ${v}`).join('\n') };
    } catch {}
  }
  return { type: 'text', display: text.substring(0, 3000) + (text.length > 3000 ? '\n…[truncated]' : '') };
}

function extractRaw(entry) {
  const reqHeaders = filterHeaders(entry.request?.headers, KEEP_REQ_HEADERS);
  // Cookie: only count, don't expose value
  const cookieHeader = entry.request?.headers?.find(h => h.name.toLowerCase() === 'cookie');
  if (cookieHeader) {
    const count = (cookieHeader.value.match(/;/g) || []).length + 1;
    reqHeaders.push({ name: 'Cookie', value: `[${count} cookie(s) present]` });
  }

  const resHeaders = filterHeaders(entry.response?.headers, KEEP_RES_HEADERS);
  // Set-Cookie: name only
  const setCookies = entry.response?.headers?.filter(h => h.name.toLowerCase() === 'set-cookie') || [];
  for (const sc of setCookies) {
    const name = sc.value.split('=')[0];
    resHeaders.push({ name: 'Set-Cookie', value: `${name}=… [value hidden]` });
  }

  const reqBody = formatBody(entry.request?.postData?.text, entry.request?.postData?.mimeType || '');
  const resBody = formatBody(entry.response?.content?.text, entry.response?.content?.mimeType || '');

  const t = entry.timings || {};
  const timing = {
    dns:     t.dns     >= 0 ? Math.round(t.dns)     : null,
    connect: t.connect >= 0 ? Math.round(t.connect) : null,
    ssl:     t.ssl     >= 0 ? Math.round(t.ssl)     : null,
    send:    t.send    >= 0 ? Math.round(t.send)    : null,
    wait:    t.wait    >= 0 ? Math.round(t.wait)    : null,
    receive: t.receive >= 0 ? Math.round(t.receive) : null,
    total:   Math.round(Object.values(t).filter(v => v > 0).reduce((a, b) => a + b, 0)),
  };

  return { reqHeaders, resHeaders, reqBody, resBody, timing };
}

// ─── Main Parse Function ──────────────────────────────────────────────────
export function parseHAR(harJson) {
  const allEntries = harJson.log?.entries || [];

  // Also include entries that redirect TO an Okta domain or Okta auth path in their Location header
  function redirectsToOkta(entry) {
    const loc = entry.response?.headers?.find(h => h.name.toLowerCase() === 'location')?.value || '';
    return isOktaDomain(loc) || /\/(oauth2|idp|login|app)\//i.test(loc);
  }

  // Also include entries that carry an iss param pointing to a known Okta-like issuer
  function hasOktaIssuer(entry) {
    try {
      const u = new URL(entry.request.url);
      const iss = u.searchParams.get('iss') || u.searchParams.get('issuer');
      return !!iss;
    } catch { return false; }
  }

  // Prefer Okta + callback + Okta-adjacent entries; fall back to all entries
  const oktaEntries = allEntries.filter(e => {
    try {
      return isOktaDomain(e.request.url) || isOktaAuthPath(e.request.url) ||
             isCallbackEntry(e) || redirectsToOkta(e) || hasOktaIssuer(e);
    } catch { return false; }
  });

  const noOktaRequests = oktaEntries.length === 0;
  const relevant = noOktaRequests ? allEntries.filter(e => e.request?.url) : oktaEntries;

  if (relevant.length === 0) {
    return { error: 'No requests found in this HAR file.' };
  }

  const protocol = detectProtocol(relevant);

  const steps = relevant.map((entry, index) => {
    const url = entry.request.url;
    const endpoint = matchEndpoint(url);
    const postBody = entry.request.postData?.text || '';

    // All text sources for artifact scanning
    const allText = [
      url,
      postBody,
      entry.response?.content?.text || '',
      JSON.stringify(entry.request?.headers || []),
      JSON.stringify(entry.response?.headers || []),
    ].join('\n');

    const jwts = findJWTs(allText);
    const saml = extractSAML(allText);
    const error = extractErrorFromResponse(entry);
    const keyParams = extractKeyParams(url, postBody);

    // Determine participants
    let from = endpoint?.from || 'browser';
    let to = endpoint?.to || 'okta';
    if (isCallbackEntry(entry) && !isOktaDomain(url)) { from = 'browser'; to = 'app'; }

    // Hostname for display
    let hostname = '';
    try { hostname = new URL(url).hostname; } catch {}

    // Okta domain from first okta URL
    let oktaDomain = '';
    try {
      if (isOktaDomain(url)) oktaDomain = new URL(url).hostname;
    } catch {}

    const status = entry.response?.status;
    const timing = Math.round((entry.timings?.wait || 0) + (entry.timings?.receive || 0));
    const raw = extractRaw(entry);

    // Extract Location header from redirects
    let locationHeader = null;
    if (status >= 300 && status < 400) {
      const loc = entry.response?.headers?.find(h => h.name.toLowerCase() === 'location');
      if (loc) locationHeader = loc.value;
    }

    return {
      index,
      name: endpoint?.name || `Request → ${hostname}`,
      description: endpoint?.description || '',
      phase: endpoint?.phase || 'other',
      from, to,
      method: entry.request.method,
      url,
      hostname,
      status,
      statusText: entry.response?.statusText || '',
      timing,
      keyParams,
      error,
      artifacts: {
        jwts: jwts.length ? jwts : null,
        saml: saml || null,
      },
      raw,
      locationHeader,
      isError: !!error,
      isRedirect: status >= 300 && status < 400,
    };
  });

  const errorSteps = steps.filter(s => s.isError);

  // Detect the Okta domain
  // A "default" Okta domain matches *.okta.com (exactly two labels, e.g. foo.okta.com).
  // A "custom" domain is anything else serving Okta auth paths (okta.company.com, login.company.com, etc.)
  let oktaDomain = 'your-org.okta.com';
  let customOktaDomain = null;
  let defaultOktaDomain = null;
  for (const e of relevant) {
    try {
      const h = new URL(e.request.url).hostname;
      const isDefault = /^[^.]+\.okta\.com$/.test(h);
      const hasOktaPath = isOktaAuthPath(e.request.url);
      if (isOktaDomain(e.request.url) || hasOktaPath) {
        if (isDefault) {
          defaultOktaDomain = defaultOktaDomain || h;
        } else if (hasOktaPath) {
          customOktaDomain = customOktaDomain || h;
        }
        oktaDomain = oktaDomain === 'your-org.okta.com' ? h : oktaDomain;
      }
    } catch {}
  }
  // Also extract custom domain from iss params in the flow
  for (const step of steps) {
    const issHost = step.keyParams?.iss ? (() => { try { return new URL(step.keyParams.iss).hostname; } catch { return null; } })() : null;
    if (issHost && issHost !== defaultOktaDomain) customOktaDomain = customOktaDomain || issHost;
  }

  // ─── Domain-switch detection ──────────────────────────────────────────────
  // Detects when an SSO flow that starts on one Okta domain (including custom/vanity
  // domains) later redirects the /authorize request to a different Okta domain.
  // This breaks SSO because sessions are domain-scoped.
  //
  // Strategy: identify all "Okta auth endpoints" (any host serving /oauth2/, /idp/,
  // /login/, /app/ Okta paths, or an iss= param pointing to a domain) and detect
  // when the host changes across the redirect chain.
  const domainSwitchWarnings = [];

  function extractIssuerDomain(url) {
    try {
      const u = new URL(url);
      const iss = u.searchParams.get('iss') || u.searchParams.get('issuer');
      if (iss) return new URL(iss).hostname;
    } catch {}
    return null;
  }

  // Collect the sequence of "auth-serving" hostnames in flow order,
  // including both actual request hosts and redirect Location targets.
  const authHostSequence = []; // [{hostname, stepIndex, source: 'request'|'location'|'iss', url}]

  for (const step of steps) {
    // ISS param in a URL tells us which domain the IdP expects
    const issHost = extractIssuerDomain(step.url);
    if (issHost) {
      authHostSequence.push({ hostname: issHost, stepIndex: step.index, source: 'iss', url: step.url });
    }

    // Any request to an Okta-style auth path
    if (isOktaDomain(step.url) || isOktaAuthPath(step.url)) {
      try {
        const h = new URL(step.url).hostname;
        authHostSequence.push({ hostname: h, stepIndex: step.index, source: 'request', url: step.url });
      } catch {}
    }

    // Location header pointing to an Okta auth path or Okta domain
    if (step.locationHeader) {
      try {
        const absLoc = step.locationHeader.startsWith('/') ? `https://${step.hostname}${step.locationHeader}` : step.locationHeader;
        const locUrl = new URL(absLoc);
        if (isOktaDomain(locUrl.hostname) || isOktaAuthPath(absLoc)) {
          authHostSequence.push({ hostname: locUrl.hostname, stepIndex: step.index, source: 'location', url: absLoc });
        }
        // Also check iss in the Location URL
        const locIss = extractIssuerDomain(absLoc);
        if (locIss) {
          authHostSequence.push({ hostname: locIss, stepIndex: step.index, source: 'iss', url: absLoc });
        }
      } catch {}
    }
  }

  // Walk the sequence and flag when hostname changes
  for (let i = 1; i < authHostSequence.length; i++) {
    const prev = authHostSequence[i - 1];
    const curr = authHostSequence[i];
    if (prev.hostname !== curr.hostname && curr.source !== 'iss') {
      // Only warn if the previous authoritative domain (from iss or actual request) differs
      // from the current auth request domain — ignore same-host changes
      domainSwitchWarnings.push({
        stepIndex: curr.stepIndex,
        from: prev.hostname,
        to: curr.hostname,
        url: curr.url,
        locationHeader: steps[curr.stepIndex]?.locationHeader || null,
        message: `Auth domain switched from ${prev.hostname} to ${curr.hostname} — SSO session will not transfer across domains`,
      });
    }
  }

  return {
    protocol,
    oktaDomain,
    customOktaDomain,
    defaultOktaDomain,
    totalSteps: steps.length,
    hasErrors: errorSteps.length > 0,
    errorCount: errorSteps.length,
    domainSwitchWarnings,
    phases: [...new Set(steps.map(s => s.phase))],
    noOktaRequests,
    steps,
  };
}

// ─── Build Claude Prompt ───────────────────────────────────────────────────
export function buildClaudePrompt(flowData) {
  const stepsText = flowData.steps.map((step, i) => {
    const parts = [`Step ${i + 1}: [${step.from.toUpperCase()} → ${step.to.toUpperCase()}] ${step.name}`];
    parts.push(`  URL: ${step.url}`);
    parts.push(`  ${step.method} | HTTP ${step.status} | ${step.timing}ms`);

    if (step.locationHeader) {
      parts.push(`  Redirect → ${step.locationHeader}`);
    }
    if (step.keyParams) {
      const p = Object.entries(step.keyParams).map(([k, v]) => `${k}=${v}`).join(', ');
      parts.push(`  Params: ${p}`);
    }
    if (step.error) {
      const e = step.error;
      parts.push(`  ⚠ ERROR ${e.status}: ${e.errorCode || ''} — ${e.errorSummary || e.raw || ''}`);
      if (e.errorCauses?.length) parts.push(`  Causes: ${e.errorCauses.join(', ')}`);
    }
    if (step.artifacts?.jwts?.length) {
      const jwt = step.artifacts.jwts[0];
      const exp = jwt.payload.exp ? new Date(jwt.payload.exp * 1000).toISOString() : 'N/A';
      const iat = jwt.payload.iat ? new Date(jwt.payload.iat * 1000).toISOString() : 'N/A';
      parts.push(`  JWT: alg=${jwt.header.alg}, typ=${jwt.header.typ}, iss=${jwt.payload.iss || 'N/A'}, sub=${jwt.payload.sub || 'N/A'}, scp=${jwt.payload.scp || jwt.payload.scope || 'N/A'}, iat=${iat}, exp=${exp}`);
    }
    if (step.artifacts?.saml) {
      const s = step.artifacts.saml;
      parts.push(`  SAML ${s.type}: issuer=${s.issuer || 'N/A'}, status=${s.status || 'N/A'}, nameID=${s.nameID || 'N/A'}`);
      if (s.notOnOrAfter) parts.push(`  SAML expiry: ${s.notOnOrAfter}`);
    }
    return parts.join('\n');
  }).join('\n\n');

  const domainSwitchSection = flowData.domainSwitchWarnings?.length
    ? `\nDOMAIN SWITCH WARNINGS (high-priority SSO session issues):\n` +
      flowData.domainSwitchWarnings.map(w =>
        `  ⚠ Step ${w.stepIndex + 1}: ${w.message}\n    From URL: ${w.url}${w.locationHeader ? `\n    Redirect to: ${w.locationHeader}` : ''}`
      ).join('\n')
    : '';

  const domainSection = flowData.customOktaDomain && flowData.defaultOktaDomain
    ? `CUSTOM DOMAIN: ${flowData.customOktaDomain}\nDEFAULT ORG DOMAIN: ${flowData.defaultOktaDomain}`
    : `ORG DOMAIN: ${flowData.oktaDomain}`;

  return `You are a senior Okta Developer Support Engineer analyzing an auth flow captured in a HAR file. Give a precise, actionable verdict.

DETECTED PROTOCOL: ${flowData.protocol}
${domainSection}
TOTAL STEPS CAPTURED: ${flowData.totalSteps}
ERRORS FOUND: ${flowData.errorCount}${domainSwitchSection}

FLOW STEPS:
${stepsText}

IMPORTANT: If you see both a custom domain and the default *.okta.com domain in the flow, pay close attention to where the switch occurs. An SSO session established on a custom domain is NOT automatically available on the default okta.com domain and vice versa — this is a common cause of unexpected re-authentication prompts.

Respond in exactly this format — no extra sections, no preamble:

## What Happened
[2-3 sentences: plain English story of what the user/app experienced, from start to finish]

## Flow Health
[One of: ✅ HEALTHY | ⚠️ WARNING | ❌ BROKEN] — [single line reason]

## Failure Point
[If HEALTHY: "No failures detected."
If WARNING/BROKEN: "Step N — [step name]: [what specifically failed — be exact about error codes, redirect mismatches, domain switches, token issues, etc.]"]

## Root Cause
[Technical deep-dive: why did it fail? Mention specific Okta error codes if present, common misconfigs (redirect URI mismatch, app not assigned, wrong auth server, MFA policy, custom domain vs default domain session isolation, etc.)]

## The Fix
[Numbered list — exact steps to resolve. If this is a third-party app domain mismatch, clearly state which party needs to fix it and what they need to change. Reference specific Okta Admin Console locations where relevant (e.g., "Applications > [App] > Sign On > Edit")]

## Verify in Okta Admin Console
[Bullet list: 3-5 specific things to check and where to find them]

Keep it sharp and technical. No generic advice.`;
}
