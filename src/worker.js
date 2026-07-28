/**
 * Lux.id Cloudflare Worker
 *
 * Deterministic Lux-branded auth surface on top of IAM APIs.
 * - No upstream HTML rewriting/scrubbing
 * - Browser auth routes always render Lux-controlled pages
 * - IAM APIs and static assets are proxied directly
 */

import { luxLogo, luxWordmark, getFaviconSVG } from '@luxfi/logo/logos';

const IAM_ORIGIN = 'https://iam.hanzo.ai';
const IAM_ORIGIN_URL = new URL(IAM_ORIGIN);
const IAM_ORIGIN_HOST = IAM_ORIGIN_URL.hostname;
const IAM_ORIGIN_BASE = IAM_ORIGIN_URL.origin;
const CANONICAL_DOMAIN = 'lux.id';
const AUTH_DOMAIN = 'iam.lux.network';
const APP_URL = 'https://cloud.lux.network';

const DEFAULT_CLIENT_ID = 'lux-web3';
const DEFAULT_SCOPE = 'openid profile email';
const DEFAULT_RESPONSE_TYPE = 'code';
const DEFAULT_REDIRECT_URI = `${APP_URL}/auth/callback`;

const BRAND = {
  name: 'Lux',
  tagline: 'Sovereign Identity',
  domain: CANONICAL_DOMAIN,
  logo: luxWordmark,
  icon: luxLogo,
  favicon: getFaviconSVG(),
  bg: '#050508',
  surface: '#0c0c10',
  border: '#222222',
};

const AUTH_PATHS = new Set([
  '/login',
  '/signup',
  '/forget',
  '/oauth/authorize',
  '/login/oauth/authorize',
  '/callback',
]);

const IAM_PREFIX_PATHS = [
  '/api/',
  '/cas/',
  '/scim/',
  '/oauth/',
  '/.well-known/',
  '/static/',
  '/locales/',
];

const IAM_EXACT_PATHS = new Set(['/manifest.json', '/robots.txt', '/oauth2/token']);

function randomState() {
  try {
    return crypto.randomUUID();
  } catch {
    return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
  }
}

function pickParam(searchParams, snakeCase, camelCase) {
  return searchParams.get(snakeCase) || searchParams.get(camelCase) || '';
}

function normalizeAuthParams(url) {
  const params = {
    clientId: pickParam(url.searchParams, 'client_id', 'clientId') || DEFAULT_CLIENT_ID,
    responseType:
      pickParam(url.searchParams, 'response_type', 'responseType') || DEFAULT_RESPONSE_TYPE,
    redirectUri:
      pickParam(url.searchParams, 'redirect_uri', 'redirectUri') || DEFAULT_REDIRECT_URI,
    scope: pickParam(url.searchParams, 'scope', 'scope') || DEFAULT_SCOPE,
    state: pickParam(url.searchParams, 'state', 'state') || randomState(),
    nonce: pickParam(url.searchParams, 'nonce', 'nonce'),
    responseMode: pickParam(url.searchParams, 'response_mode', 'responseMode'),
    challengeMethod: pickParam(
      url.searchParams,
      'code_challenge_method',
      'codeChallengeMethod',
    ),
    codeChallenge: pickParam(url.searchParams, 'code_challenge', 'codeChallenge'),
  };

  return params;
}

function buildAuthSearchParams(auth) {
  const params = new URLSearchParams();
  params.set('client_id', auth.clientId);
  params.set('response_type', auth.responseType);
  params.set('redirect_uri', auth.redirectUri);
  params.set('scope', auth.scope);
  params.set('state', auth.state);

  if (auth.nonce) params.set('nonce', auth.nonce);
  if (auth.responseMode) params.set('response_mode', auth.responseMode);
  if (auth.challengeMethod) params.set('code_challenge_method', auth.challengeMethod);
  if (auth.codeChallenge) params.set('code_challenge', auth.codeChallenge);

  return params;
}

function buildIamApiSearchParams(auth) {
  const params = new URLSearchParams();
  params.set('clientId', auth.clientId);
  params.set('responseType', auth.responseType);
  params.set('redirectUri', auth.redirectUri);
  params.set('scope', auth.scope);
  params.set('state', auth.state);
  params.set('type', auth.responseType || DEFAULT_RESPONSE_TYPE);

  if (auth.nonce) params.set('nonce', auth.nonce);
  if (auth.responseMode) params.set('responseMode', auth.responseMode);
  if (auth.challengeMethod) params.set('code_challenge_method', auth.challengeMethod);
  if (auth.codeChallenge) params.set('code_challenge', auth.codeChallenge);

  return params;
}

function shouldProxyToIAM(pathname) {
  // ACME challenges must pass through to K8s origin (cert-manager solver pod)
  if (pathname.startsWith('/.well-known/acme-challenge/')) {
    return false;
  }

  if (IAM_EXACT_PATHS.has(pathname)) {
    return true;
  }

  return IAM_PREFIX_PATHS.some((prefix) => pathname.startsWith(prefix));
}

function isAuthSurfacePath(pathname) {
  return AUTH_PATHS.has(pathname) || shouldProxyToIAM(pathname);
}

function getOgImageSvg() {
  return `<svg width="1200" height="630" viewBox="0 0 1200 630" xmlns="http://www.w3.org/2000/svg">
  <rect width="1200" height="630" fill="${BRAND.bg}"/>
  <g transform="translate(500, 200)">
    ${luxLogo.replace('viewBox="0 0 100 100"', 'viewBox="0 0 100 100" width="200" height="200"')}
  </g>
  <text x="600" y="480" font-family="system-ui, -apple-system, sans-serif" font-size="32" font-weight="400" fill="#666666" text-anchor="middle">${BRAND.tagline}</text>
</svg>`;
}

function serveBrandingAsset(pathname) {
  if (pathname === '/og-image.svg' || pathname === '/og-image.png') {
    return new Response(getOgImageSvg(), {
      headers: {
        'content-type': 'image/svg+xml',
        'cache-control': 'public, max-age=86400',
      },
    });
  }

  if (pathname.includes('logo') && (pathname.endsWith('.svg') || pathname.endsWith('.png'))) {
    return new Response(BRAND.logo, {
      headers: {
        'content-type': 'image/svg+xml',
        'cache-control': 'public, max-age=86400',
      },
    });
  }

  if (pathname.includes('favicon') || pathname === '/img/lux-favicon.svg') {
    return new Response(BRAND.favicon, {
      headers: {
        'content-type': 'image/svg+xml',
        'cache-control': 'public, max-age=86400',
      },
    });
  }

  if (pathname === '/cdn/img/logo-white.svg' || pathname === '/cdn/img/logo.svg') {
    return new Response(BRAND.logo, {
      headers: {
        'content-type': 'image/svg+xml',
        'cache-control': 'public, max-age=86400',
      },
    });
  }

  if (pathname === '/cdn/img/favicon.png' || pathname === '/cdn/img/favicon.svg') {
    return new Response(BRAND.favicon, {
      headers: {
        'content-type': 'image/svg+xml',
        'cache-control': 'public, max-age=86400',
      },
    });
  }

  if (pathname === '/cdn/img/icon.svg' || pathname === '/icon.svg') {
    return new Response(BRAND.icon, {
      headers: {
        'content-type': 'image/svg+xml',
        'cache-control': 'public, max-age=86400',
      },
    });
  }

  return null;
}

function htmlResponse(html) {
  return new Response(html, {
    headers: {
      'content-type': 'text/html;charset=UTF-8',
      'cache-control': 'no-store',
    },
  });
}

function escapeInlineJson(value) {
  return JSON.stringify(value).replace(/</g, '\\u003c');
}

function renderLandingPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${BRAND.name} ID - ${BRAND.tagline}</title>
  <meta name="description" content="${BRAND.tagline} for the Lux Network">
  <link rel="icon" type="image/svg+xml" href="/cdn/img/favicon.svg">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: ${BRAND.bg};
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
      padding: 2rem;
    }
    .card {
      width: 100%;
      max-width: 560px;
      border: 1px solid ${BRAND.border};
      border-radius: 16px;
      background: ${BRAND.surface};
      padding: 2rem;
      text-align: center;
    }
    .logo svg { height: 56px; width: auto; }
    .wordmark { margin-top: 1rem; }
    .wordmark svg { height: 28px; width: auto; }
    h1 {
      margin-top: 1rem;
      font-size: 1.5rem;
      font-weight: 600;
    }
    p {
      margin-top: 0.75rem;
      color: #9b9b9b;
      line-height: 1.6;
    }
    .actions {
      margin-top: 1.5rem;
      display: flex;
      gap: 0.75rem;
      justify-content: center;
      flex-wrap: wrap;
    }
    .btn {
      display: inline-block;
      border-radius: 8px;
      padding: 0.7rem 1.2rem;
      text-decoration: none;
      font-weight: 600;
      border: 1px solid ${BRAND.border};
    }
    .btn-primary {
      background: #fff;
      color: #111;
      border-color: #fff;
    }
    .btn-secondary {
      color: #f1f1f1;
    }
  </style>
</head>
<body>
  <main class="card">
    <div class="logo">${BRAND.icon}</div>
    <div class="wordmark">${BRAND.logo}</div>
    <h1>${BRAND.tagline}</h1>
    <p>Sign in with Lux Identity for secure access to Lux services.</p>
    <div class="actions">
      <a class="btn btn-primary" href="https://${AUTH_DOMAIN}/login">Sign In</a>
      <a class="btn btn-secondary" href="${APP_URL}">Back to Lux Cloud</a>
    </div>
  </main>
</body>
</html>`;
}

function renderLoginPage(auth) {
  const authSearchParams = buildAuthSearchParams(auth);
  const apiSearchParams = buildIamApiSearchParams(auth);

  const scriptPayload = {
    auth,
    authQuery: authSearchParams.toString(),
    apiQuery: apiSearchParams.toString(),
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In - ${BRAND.name} ID</title>
  <meta name="description" content="${BRAND.tagline}">
  <link rel="icon" type="image/svg+xml" href="/cdn/img/favicon.svg">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: ${BRAND.bg};
      color: #fff;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.25rem;
    }
    .layout {
      width: 100%;
      max-width: 920px;
      display: grid;
      grid-template-columns: 1fr 1fr;
      border: 1px solid ${BRAND.border};
      border-radius: 16px;
      overflow: hidden;
      background: ${BRAND.surface};
    }
    .brand {
      background: ${BRAND.bg};
      border-right: 1px solid ${BRAND.border};
      padding: 2rem;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      text-align: center;
      gap: 1rem;
    }
    .brand .icon svg { height: 60px; width: auto; }
    .brand .wordmark svg { height: 32px; width: auto; }
    .brand .tagline {
      color: #8b8b8b;
      font-size: 0.86rem;
      letter-spacing: 0.14em;
      text-transform: uppercase;
    }
    .brand .copy {
      color: #9c9c9c;
      line-height: 1.7;
      max-width: 300px;
    }
    .panel {
      padding: 2rem;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .panel-inner {
      width: 100%;
      max-width: 360px;
    }
    h1 {
      font-size: 1.55rem;
      font-weight: 600;
      margin-bottom: 0.35rem;
    }
    .subtitle {
      color: #8f8f8f;
      margin-bottom: 1.25rem;
      font-size: 0.92rem;
    }
    .field { margin-bottom: 0.9rem; }
    label {
      display: block;
      margin-bottom: 0.4rem;
      color: #b3b3b3;
      font-size: 0.82rem;
    }
    input {
      width: 100%;
      border-radius: 8px;
      border: 1px solid ${BRAND.border};
      background: ${BRAND.bg};
      color: #fff;
      padding: 0.72rem 0.85rem;
      font-size: 0.94rem;
    }
    input:focus {
      outline: none;
      border-color: #555;
    }
    .error {
      display: none;
      margin-bottom: 0.9rem;
      color: #ff8f8f;
      font-size: 0.82rem;
      line-height: 1.5;
    }
    .status {
      margin-bottom: 0.9rem;
      color: #8f8f8f;
      font-size: 0.82rem;
      line-height: 1.5;
    }
    .submit {
      width: 100%;
      border: 1px solid #fff;
      background: #fff;
      color: #111;
      border-radius: 8px;
      padding: 0.72rem 0.85rem;
      font-weight: 600;
      cursor: pointer;
    }
    .submit:disabled {
      opacity: 0.6;
      cursor: wait;
    }
    .links {
      margin-top: 1rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.8rem;
      font-size: 0.82rem;
    }
    a {
      color: #9a9a9a;
      text-decoration: none;
    }
    a:hover { color: #fff; }
    @media (max-width: 860px) {
      .layout {
        grid-template-columns: 1fr;
      }
      .brand {
        border-right: none;
        border-bottom: 1px solid ${BRAND.border};
      }
    }
  </style>
</head>
<body>
  <main class="layout">
    <section class="brand">
      <div class="icon">${BRAND.icon}</div>
      <div class="wordmark">${BRAND.logo}</div>
      <p class="tagline">${BRAND.tagline}</p>
      <p class="copy">Production IAM endpoint for Lux Network applications.</p>
    </section>
    <section class="panel">
      <div class="panel-inner">
        <h1>Sign in</h1>
        <p class="subtitle">Use your Lux account to continue.</p>

        <div class="social-buttons" style="display:flex;flex-direction:column;gap:0.6rem;margin-bottom:1.25rem;">
          <button type="button" id="btn-github" class="social-btn" style="display:flex;align-items:center;justify-content:center;gap:0.6rem;width:100%;padding:0.72rem;border-radius:8px;border:1px solid ${BRAND.border};background:${BRAND.bg};color:#fff;font-size:0.92rem;font-weight:500;cursor:pointer;">
            <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18"><path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0 0 22 12.017C22 6.484 17.522 2 12 2z"/></svg>
            Continue with GitHub
          </button>
          <button type="button" id="btn-google" class="social-btn" style="display:flex;align-items:center;justify-content:center;gap:0.6rem;width:100%;padding:0.72rem;border-radius:8px;border:1px solid ${BRAND.border};background:${BRAND.bg};color:#fff;font-size:0.92rem;font-weight:500;cursor:pointer;">
            <svg viewBox="0 0 24 24" width="18" height="18"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
            Continue with Google
          </button>
          <button type="button" id="btn-wallet" class="social-btn" style="display:flex;align-items:center;justify-content:center;gap:0.6rem;width:100%;padding:0.72rem;border-radius:8px;border:1px solid #2a2a4a;background:linear-gradient(135deg, #1a1a2e, #16213e);color:#fff;font-size:0.92rem;font-weight:500;cursor:pointer;">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>
            Connect Wallet
          </button>
        </div>
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:1.25rem;color:#555;font-size:0.78rem;text-transform:uppercase;letter-spacing:0.05em;">
          <span style="flex:1;height:1px;background:#222;"></span> or <span style="flex:1;height:1px;background:#222;"></span>
        </div>

        <div class="status" id="status">Loading application settings...</div>
        <div class="error" id="error"></div>

        <form id="login-form" novalidate>
          <div class="field">
            <div style="display:flex;align-items:center;justify-content:space-between;">
              <label id="login-contact-label" for="username" style="margin:0;">Email or username</label>
              <button type="button" id="login-contact-toggle" style="background:none;border:1px solid #333;color:#888;font-size:0.78em;padding:0.15rem 0.5rem;border-radius:4px;cursor:pointer;">Use phone</button>
            </div>
            <input id="username" name="username" autocomplete="username" required>
          </div>
          <div class="field">
            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="current-password" required>
          </div>
          <button class="submit" id="submit" type="submit">Sign In</button>
        </form>

        <div class="links">
          <a href="/signup?${authSearchParams.toString()}">Create account</a>
          <a href="/forget?${authSearchParams.toString()}">Forgot password?</a>
        </div>
      </div>
    </section>
  </main>

  <script>
    const payload = ${escapeInlineJson(scriptPayload)};
    const auth = payload.auth;
    const statusEl = document.getElementById('status');
    const errorEl = document.getElementById('error');
    const formEl = document.getElementById('login-form');
    const submitEl = document.getElementById('submit');

    let app = null;

    function showError(message) {
      errorEl.textContent = message;
      errorEl.style.display = 'block';
    }

    function clearError() {
      errorEl.textContent = '';
      errorEl.style.display = 'none';
    }

    async function loadAppLogin() {
      const response = await fetch('/api/get-app-login?' + payload.apiQuery, {
        method: 'GET',
        credentials: 'include',
      });

      const result = await response.json();
      if (result.status !== 'ok' || !result.data) {
        throw new Error(result.msg || 'Unable to load login configuration');
      }

      app = result.data;
      statusEl.textContent = app.displayName
        ? 'Signing into ' + app.displayName
        : 'Ready to sign in';
    }

    async function login(username, password) {
      if (!app) {
        throw new Error('Login configuration not loaded');
      }

      const body = {
        username,
        password,
        application: app.name,
        organization: app.organization,
        signinMethod: 'Password',
        type: auth.responseType || 'code',
        language: navigator.language || 'en',
      };

      const response = await fetch('/api/login?' + payload.apiQuery, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(body),
      });

      if (!response.ok && response.status === 403) {
        throw new Error('Invalid username or password');
      }

      let result;
      try {
        result = await response.json();
      } catch {
        throw new Error('Invalid username or password');
      }

      if (result.status !== 'ok') {
        throw new Error(result.msg || 'Sign in failed');
      }

      if ((auth.responseType || 'code') !== 'code') {
        throw new Error('Unsupported response_type for Lux login flow');
      }

      if (!result.data) {
        throw new Error('Authorization code missing from IAM response');
      }

      const redirect = new URL(auth.redirectUri);
      redirect.searchParams.set('code', result.data);
      if (auth.state) {
        redirect.searchParams.set('state', auth.state);
      }
      window.location.assign(redirect.toString());
    }

    // Login contact toggle (email ↔ phone)
    (function() {
      let mode = 'email';
      const inp = document.getElementById('username');
      const lbl = document.getElementById('login-contact-label');
      const btn = document.getElementById('login-contact-toggle');
      btn.addEventListener('click', function() {
        if (mode === 'email') {
          mode = 'phone';
          inp.type = 'tel';
          inp.placeholder = '+1 (555) 000-0000';
          inp.autocomplete = 'tel';
          inp.value = '';
          lbl.textContent = 'Phone number';
          btn.textContent = 'Use email';
        } else {
          mode = 'email';
          inp.type = 'text';
          inp.placeholder = '';
          inp.autocomplete = 'username';
          inp.value = '';
          lbl.textContent = 'Email or username';
          btn.textContent = 'Use phone';
        }
      });
    })();

    formEl.addEventListener('submit', async (event) => {
      event.preventDefault();
      clearError();

      const username = document.getElementById('username').value.trim();
      const password = document.getElementById('password').value;

      if (!username || !password) {
        showError('Enter both username and password.');
        return;
      }

      submitEl.disabled = true;
      submitEl.textContent = 'Signing in...';

      try {
        await login(username, password);
      } catch (error) {
        showError(error instanceof Error ? error.message : 'Sign in failed');
        submitEl.disabled = false;
        submitEl.textContent = 'Sign In';
      }
    });

    // Social login handlers
    function socialLogin(provider) {
      var params = new URLSearchParams({
        client_id: auth.clientId,
        redirect_uri: auth.redirectUri,
        response_type: auth.responseType || 'code',
        scope: auth.scope,
        state: auth.state,
        provider: provider,
      });
      window.location.href = '/oauth/authorize?' + params.toString();
    }

    document.getElementById('btn-github').addEventListener('click', function() {
      socialLogin('provider-github');
    });
    document.getElementById('btn-google').addEventListener('click', function() {
      socialLogin('provider-google');
    });

    // Web3 wallet login — client-side EIP-712 typed data flow
    async function walletLogin() {
      if (typeof window.ethereum === 'undefined') {
        showError('Please install MetaMask or another Web3 wallet.');
        return;
      }
      try {
        var accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        var address = accounts[0];
        var nonce = crypto.randomUUID();
        var now = new Date();
        var typedData = JSON.stringify({
          domain: { chainId: window.ethereum.chainId, name: 'Hanzo IAM', version: '1' },
          message: {
            prompt: 'In order to authenticate to this website, sign this request and your public address will be sent to the server in a verifiable way.',
            nonce: nonce,
            createAt: now.toLocaleString()
          },
          primaryType: 'AuthRequest',
          types: {
            EIP712Domain: [
              { name: 'name', type: 'string' },
              { name: 'version', type: 'string' },
              { name: 'chainId', type: 'uint256' }
            ],
            AuthRequest: [
              { name: 'prompt', type: 'string' },
              { name: 'nonce', type: 'string' },
              { name: 'createAt', type: 'string' }
            ]
          }
        });
        var signature = await window.ethereum.request({
          method: 'eth_signTypedData_v4',
          params: [address, typedData]
        });
        var web3Code = JSON.stringify({ address: address, typedData: typedData, signature: signature });

        if (!app) await loadAppLogin();

        var params = new URLSearchParams(payload.apiQuery);
        params.set('state', 'hanzo');

        var res = await fetch('/api/login?' + params.toString(), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            method: 'signup',
            type: auth.responseType || 'code',
            application: app.name,
            organization: app.organization,
            provider: 'provider-web3',
            code: web3Code,
            state: 'hanzo',
            redirectUri: auth.redirectUri,
          }),
        });

        var data = await res.json();
        if (data.status === 'ok' && data.data) {
          var redirect = new URL(auth.redirectUri);
          redirect.searchParams.set('code', data.data);
          if (auth.state) redirect.searchParams.set('state', auth.state);
          window.location.assign(redirect.toString());
        } else {
          showError(data.msg || 'Web3 login failed');
        }
      } catch (err) {
        if (err.code === 4001) return;
        showError(err.message || 'Failed to connect wallet');
      }
    }

    document.getElementById('btn-wallet').addEventListener('click', function() {
      walletLogin();
    });

    loadAppLogin().catch((error) => {
      showError(error instanceof Error ? error.message : 'Unable to initialize login flow');
      statusEl.textContent = 'Login unavailable';
      submitEl.disabled = true;
    });
  </script>
</body>
</html>`;
}

function renderSignupPage(auth) {
  const authSearchParams = buildAuthSearchParams(auth);
  const apiSearchParams = buildIamApiSearchParams(auth);

  const scriptPayload = {
    auth,
    authQuery: authSearchParams.toString(),
    apiQuery: apiSearchParams.toString(),
  };

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Create Account - ${BRAND.name} ID</title>
  <meta name="description" content="${BRAND.tagline}">
  <link rel="icon" type="image/svg+xml" href="/cdn/img/favicon.svg">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: ${BRAND.bg};
      color: #fff;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.25rem;
    }
    .layout {
      width: 100%;
      max-width: 920px;
      display: grid;
      grid-template-columns: 1fr 1fr;
      border: 1px solid ${BRAND.border};
      border-radius: 16px;
      overflow: hidden;
      background: ${BRAND.surface};
    }
    .brand {
      background: ${BRAND.bg};
      border-right: 1px solid ${BRAND.border};
      padding: 2rem;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      text-align: center;
      gap: 1rem;
    }
    .brand .icon svg { height: 60px; width: auto; }
    .brand .wordmark svg { height: 32px; width: auto; }
    .brand .tagline {
      color: #8b8b8b;
      font-size: 0.86rem;
      letter-spacing: 0.14em;
      text-transform: uppercase;
    }
    .brand .copy {
      color: #9c9c9c;
      line-height: 1.7;
      max-width: 300px;
    }
    .panel {
      padding: 2rem;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .panel-inner {
      width: 100%;
      max-width: 360px;
    }
    h1 {
      font-size: 1.55rem;
      font-weight: 600;
      margin-bottom: 0.35rem;
    }
    .subtitle {
      color: #8f8f8f;
      margin-bottom: 1.25rem;
      font-size: 0.92rem;
    }
    .field { margin-bottom: 0.9rem; }
    label {
      display: block;
      margin-bottom: 0.4rem;
      color: #b3b3b3;
      font-size: 0.82rem;
    }
    input {
      width: 100%;
      border-radius: 8px;
      border: 1px solid ${BRAND.border};
      background: ${BRAND.bg};
      color: #fff;
      padding: 0.72rem 0.85rem;
      font-size: 0.94rem;
    }
    input:focus {
      outline: none;
      border-color: #555;
    }
    .error {
      display: none;
      margin-bottom: 0.9rem;
      color: #ff8f8f;
      font-size: 0.82rem;
      line-height: 1.5;
    }
    .status {
      margin-bottom: 0.9rem;
      color: #8f8f8f;
      font-size: 0.82rem;
      line-height: 1.5;
    }
    .submit {
      width: 100%;
      border: 1px solid #fff;
      background: #fff;
      color: #111;
      border-radius: 8px;
      padding: 0.72rem 0.85rem;
      font-weight: 600;
      cursor: pointer;
    }
    .submit:disabled {
      opacity: 0.6;
      cursor: wait;
    }
    .links {
      margin-top: 1rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.8rem;
      font-size: 0.82rem;
    }
    a {
      color: #9a9a9a;
      text-decoration: none;
    }
    a:hover { color: #fff; }
    @media (max-width: 860px) {
      .layout {
        grid-template-columns: 1fr;
      }
      .brand {
        border-right: none;
        border-bottom: 1px solid ${BRAND.border};
      }
    }
  </style>
</head>
<body>
  <main class="layout">
    <section class="brand">
      <div class="icon">${BRAND.icon}</div>
      <div class="wordmark">${BRAND.logo}</div>
      <p class="tagline">${BRAND.tagline}</p>
      <p class="copy">Create your Lux identity for access to Lux Network services.</p>
    </section>
    <section class="panel">
      <div class="panel-inner">
        <h1>Create account</h1>
        <p class="subtitle">Set up your Lux identity.</p>

        <div class="social-buttons" style="display:flex;flex-direction:column;gap:0.6rem;margin-bottom:1.25rem;">
          <button type="button" id="btn-github" class="social-btn" style="display:flex;align-items:center;justify-content:center;gap:0.6rem;width:100%;padding:0.72rem;border-radius:8px;border:1px solid ${BRAND.border};background:${BRAND.bg};color:#fff;font-size:0.92rem;font-weight:500;cursor:pointer;">
            <svg viewBox="0 0 24 24" fill="currentColor" width="18" height="18"><path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0 0 22 12.017C22 6.484 17.522 2 12 2z"/></svg>
            Sign up with GitHub
          </button>
          <button type="button" id="btn-google" class="social-btn" style="display:flex;align-items:center;justify-content:center;gap:0.6rem;width:100%;padding:0.72rem;border-radius:8px;border:1px solid ${BRAND.border};background:${BRAND.bg};color:#fff;font-size:0.92rem;font-weight:500;cursor:pointer;">
            <svg viewBox="0 0 24 24" width="18" height="18"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/></svg>
            Sign up with Google
          </button>
          <button type="button" id="btn-wallet" class="social-btn" style="display:flex;align-items:center;justify-content:center;gap:0.6rem;width:100%;padding:0.72rem;border-radius:8px;border:1px solid #2a2a4a;background:linear-gradient(135deg, #1a1a2e, #16213e);color:#fff;font-size:0.92rem;font-weight:500;cursor:pointer;">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="18" height="18"><rect x="1" y="4" width="22" height="16" rx="2" ry="2"/><line x1="1" y1="10" x2="23" y2="10"/></svg>
            Connect Wallet
          </button>
        </div>
        <div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:1.25rem;color:#555;font-size:0.78rem;text-transform:uppercase;letter-spacing:0.05em;">
          <span style="flex:1;height:1px;background:#222;"></span> or sign up with email <span style="flex:1;height:1px;background:#222;"></span>
        </div>

        <div class="status" id="status">Loading...</div>
        <div class="error" id="error"></div>

        <form id="signup-form" novalidate>
          <div class="field">
            <label for="username">Username</label>
            <input id="username" name="username" autocomplete="username" required placeholder="Choose a username">
          </div>
          <div class="field">
            <label for="name">Display name</label>
            <input id="name" name="name" autocomplete="name" required placeholder="Your name">
          </div>
          <div class="field">
            <div style="display:flex;align-items:center;justify-content:space-between;">
              <label id="contact-label" for="contact" style="margin:0;">Email</label>
              <button type="button" id="contact-toggle" style="background:none;border:1px solid #333;color:#888;font-size:0.78em;padding:0.15rem 0.5rem;border-radius:4px;cursor:pointer;">Use phone instead</button>
            </div>
            <input id="contact" name="contact" type="email" autocomplete="email" required placeholder="you@example.com">
          </div>
          <div class="field">
            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="new-password" required placeholder="At least 8 characters">
          </div>
          <div class="field">
            <label for="confirm">Confirm password</label>
            <input id="confirm" name="confirm" type="password" autocomplete="new-password" required>
          </div>
          <button class="submit" id="submit" type="submit">Create Account</button>
        </form>

        <div class="links">
          <a href="/login?${authSearchParams.toString()}">Already have an account? Sign in</a>
          <a href="/forget?${authSearchParams.toString()}">Forgot password?</a>
        </div>
      </div>
    </section>
  </main>

  <script>
    const payload = ${escapeInlineJson(scriptPayload)};
    const auth = payload.auth;
    const statusEl = document.getElementById('status');
    const errorEl = document.getElementById('error');
    const formEl = document.getElementById('signup-form');
    const submitEl = document.getElementById('submit');

    let app = null;

    function showError(message) {
      errorEl.textContent = message;
      errorEl.style.display = 'block';
    }

    function clearError() {
      errorEl.textContent = '';
      errorEl.style.display = 'none';
    }

    async function loadAppLogin() {
      const response = await fetch('/api/get-app-login?' + payload.apiQuery, {
        method: 'GET',
        credentials: 'include',
      });

      const result = await response.json();
      if (result.status !== 'ok' || !result.data) {
        throw new Error(result.msg || 'Unable to load application');
      }

      app = result.data;
      statusEl.textContent = 'Create your ' + (app.displayName || 'Lux') + ' account';
    }

    // Social OAuth — redirect to worker's authorize endpoint
    function socialLogin(provider) {
      var params = new URLSearchParams(payload.apiQuery);
      params.set('provider', provider);
      window.location.href = '/oauth/authorize?' + params.toString();
    }

    document.getElementById('btn-github').addEventListener('click', function() { socialLogin('provider-github'); });
    document.getElementById('btn-google').addEventListener('click', function() { socialLogin('provider-google'); });

    // Web3 wallet signup — EIP-712 typed data flow
    async function walletLogin() {
      if (typeof window.ethereum === 'undefined') {
        showError('Please install MetaMask or another Web3 wallet.');
        return;
      }
      try {
        var accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        var address = accounts[0];
        var nonce = crypto.randomUUID();
        var now = new Date();
        var typedData = JSON.stringify({
          domain: { chainId: window.ethereum.chainId, name: 'Hanzo IAM', version: '1' },
          message: {
            prompt: 'In order to authenticate to this website, sign this request and your public address will be sent to the server in a verifiable way.',
            nonce: nonce,
            createAt: now.toLocaleString()
          },
          primaryType: 'AuthRequest',
          types: {
            EIP712Domain: [
              { name: 'name', type: 'string' },
              { name: 'version', type: 'string' },
              { name: 'chainId', type: 'uint256' }
            ],
            AuthRequest: [
              { name: 'prompt', type: 'string' },
              { name: 'nonce', type: 'string' },
              { name: 'createAt', type: 'string' }
            ]
          }
        });
        var signature = await window.ethereum.request({
          method: 'eth_signTypedData_v4',
          params: [address, typedData]
        });
        var web3Code = JSON.stringify({ address: address, typedData: typedData, signature: signature });

        if (!app) await loadAppLogin();

        var params = new URLSearchParams(payload.apiQuery);
        params.set('state', 'hanzo');

        var res = await fetch('/api/login?' + params.toString(), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            method: 'signup',
            type: auth.responseType || 'code',
            application: app.name,
            organization: app.organization,
            provider: 'provider-web3',
            code: web3Code,
            state: 'hanzo',
            redirectUri: auth.redirectUri,
          }),
        });

        var data = await res.json();
        if (data.status === 'ok' && data.data) {
          var redirect = new URL(auth.redirectUri);
          redirect.searchParams.set('code', data.data);
          if (auth.state) redirect.searchParams.set('state', auth.state);
          window.location.assign(redirect.toString());
        } else {
          showError(data.msg || 'Web3 signup failed');
        }
      } catch (err) {
        if (err.code === 4001) return;
        showError(err.message || 'Failed to connect wallet');
      }
    }

    document.getElementById('btn-wallet').addEventListener('click', function() { walletLogin(); });

    // Contact field toggle (email ↔ phone)
    let contactMode = 'email';
    const contactInput = document.getElementById('contact');
    const contactLabel = document.getElementById('contact-label');
    const contactToggle = document.getElementById('contact-toggle');
    contactToggle.addEventListener('click', function() {
      if (contactMode === 'email') {
        contactMode = 'phone';
        contactInput.type = 'tel';
        contactInput.placeholder = '+1 (555) 000-0000';
        contactInput.autocomplete = 'tel';
        contactInput.value = '';
        contactLabel.textContent = 'Phone';
        contactToggle.textContent = 'Use email instead';
      } else {
        contactMode = 'email';
        contactInput.type = 'email';
        contactInput.placeholder = 'you@example.com';
        contactInput.autocomplete = 'email';
        contactInput.value = '';
        contactLabel.textContent = 'Email';
        contactToggle.textContent = 'Use phone instead';
      }
    });

    async function signup(username, name, email, phone, password) {
      if (!app) {
        throw new Error('Application not loaded');
      }

      const body = {
        application: app.name,
        organization: app.organization,
        username,
        name,
        email,
        phone: phone || '',
        password,
        type: 'normal-user',
        language: navigator.language || 'en',
      };

      const response = await fetch('/api/signup?' + payload.apiQuery, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'content-type': 'application/json',
        },
        body: JSON.stringify(body),
      });

      let result;
      try {
        result = await response.json();
      } catch {
        throw new Error('Signup failed. Please try again.');
      }

      if (result.status !== 'ok') {
        throw new Error(result.msg || 'Signup failed');
      }

      // Redirect to login after successful signup
      window.location.assign('/login?' + payload.authQuery);
    }

    formEl.addEventListener('submit', async (event) => {
      event.preventDefault();
      clearError();

      const username = document.getElementById('username').value.trim();
      const name = document.getElementById('name').value.trim();
      const contactVal = contactInput.value.trim();
      const email = contactMode === 'email' ? contactVal : '';
      const phone = contactMode === 'phone' ? contactVal : '';
      const password = document.getElementById('password').value;
      const confirm = document.getElementById('confirm').value;

      if (!username || !name || !contactVal || !password) {
        showError('All fields are required.');
        return;
      }

      if (password !== confirm) {
        showError('Passwords do not match.');
        return;
      }

      if (password.length < 8) {
        showError('Password must be at least 8 characters.');
        return;
      }

      submitEl.disabled = true;
      submitEl.textContent = 'Creating account...';

      try {
        await signup(username, name, email, phone, password);
      } catch (error) {
        showError(error instanceof Error ? error.message : 'Signup failed');
        submitEl.disabled = false;
        submitEl.textContent = 'Create Account';
      }
    });

    loadAppLogin().catch((error) => {
      showError(error instanceof Error ? error.message : 'Unable to initialize');
      statusEl.textContent = 'Signup unavailable';
      submitEl.disabled = true;
    });
  </script>
</body>
</html>`;
}

function renderForgotPage(auth) {
  const authSearchParams = buildAuthSearchParams(auth);
  const apiSearchParams = buildIamApiSearchParams(auth);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Password - ${BRAND.name} ID</title>
  <meta name="description" content="${BRAND.tagline}">
  <link rel="icon" type="image/svg+xml" href="/cdn/img/favicon.svg">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: ${BRAND.bg};
      color: #fff;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 1.25rem;
    }
    .layout {
      width: 100%;
      max-width: 920px;
      display: grid;
      grid-template-columns: 1fr 1fr;
      border: 1px solid ${BRAND.border};
      border-radius: 16px;
      overflow: hidden;
      background: ${BRAND.surface};
    }
    .brand {
      background: ${BRAND.bg};
      border-right: 1px solid ${BRAND.border};
      padding: 2rem;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
      text-align: center;
      gap: 1rem;
    }
    .brand .icon svg { height: 60px; width: auto; }
    .brand .wordmark svg { height: 32px; width: auto; }
    .brand .tagline {
      color: #8b8b8b;
      font-size: 0.86rem;
      letter-spacing: 0.14em;
      text-transform: uppercase;
    }
    .panel {
      padding: 2rem;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .panel-inner {
      width: 100%;
      max-width: 360px;
    }
    h1 {
      font-size: 1.55rem;
      font-weight: 600;
      margin-bottom: 0.35rem;
    }
    .subtitle {
      color: #8f8f8f;
      margin-bottom: 1.25rem;
      font-size: 0.92rem;
    }
    .field { margin-bottom: 0.9rem; }
    label {
      display: block;
      margin-bottom: 0.4rem;
      color: #b3b3b3;
      font-size: 0.82rem;
    }
    input {
      width: 100%;
      border-radius: 8px;
      border: 1px solid ${BRAND.border};
      background: ${BRAND.bg};
      color: #fff;
      padding: 0.72rem 0.85rem;
      font-size: 0.94rem;
    }
    input:focus {
      outline: none;
      border-color: #555;
    }
    .error {
      display: none;
      margin-bottom: 0.9rem;
      color: #ff8f8f;
      font-size: 0.82rem;
      line-height: 1.5;
    }
    .success {
      display: none;
      margin-bottom: 0.9rem;
      color: #8fdf8f;
      font-size: 0.82rem;
      line-height: 1.5;
    }
    .submit {
      width: 100%;
      border: 1px solid #fff;
      background: #fff;
      color: #111;
      border-radius: 8px;
      padding: 0.72rem 0.85rem;
      font-weight: 600;
      cursor: pointer;
    }
    .submit:disabled {
      opacity: 0.6;
      cursor: wait;
    }
    .links {
      margin-top: 1rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.8rem;
      font-size: 0.82rem;
    }
    a {
      color: #9a9a9a;
      text-decoration: none;
    }
    a:hover { color: #fff; }
    @media (max-width: 860px) {
      .layout {
        grid-template-columns: 1fr;
      }
      .brand {
        border-right: none;
        border-bottom: 1px solid ${BRAND.border};
      }
    }
  </style>
</head>
<body>
  <main class="layout">
    <section class="brand">
      <div class="icon">${BRAND.icon}</div>
      <div class="wordmark">${BRAND.logo}</div>
      <p class="tagline">${BRAND.tagline}</p>
    </section>
    <section class="panel">
      <div class="panel-inner">
        <h1>Reset password</h1>
        <p class="subtitle">Enter your email and we'll send you a reset link.</p>

        <div class="error" id="error"></div>
        <div class="success" id="success"></div>

        <form id="forgot-form" novalidate>
          <div class="field">
            <label for="email">Email address</label>
            <input id="email" name="email" type="email" autocomplete="email" required placeholder="you@example.com">
          </div>
          <button class="submit" id="submit" type="submit">Send reset link</button>
        </form>

        <div class="links">
          <a href="/login?${authSearchParams.toString()}">Back to sign in</a>
          <a href="/signup?${authSearchParams.toString()}">Create account</a>
        </div>
      </div>
    </section>
  </main>

  <script>
    const formEl = document.getElementById('forgot-form');
    const errorEl = document.getElementById('error');
    const successEl = document.getElementById('success');
    const submitEl = document.getElementById('submit');

    formEl.addEventListener('submit', async function(e) {
      e.preventDefault();
      errorEl.style.display = 'none';
      successEl.style.display = 'none';

      var email = document.getElementById('email').value.trim();
      if (!email) {
        errorEl.textContent = 'Please enter your email address.';
        errorEl.style.display = 'block';
        return;
      }

      submitEl.disabled = true;
      submitEl.textContent = 'Sending...';

      try {
        var res = await fetch('/api/send-verification-code', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            dest: email,
            type: 'email',
            applicationId: 'admin/${auth.clientId === 'lux-web3' ? 'app-lux-web3' : 'app-lux'}',
            method: 'forget',
          }),
        });
        var data = await res.json();
        submitEl.disabled = false;
        submitEl.textContent = 'Send reset link';
        // Always show success for security (don't reveal if email exists)
        successEl.textContent = 'If an account exists with that email, you will receive a reset link shortly.';
        successEl.style.display = 'block';
      } catch (err) {
        submitEl.disabled = false;
        submitEl.textContent = 'Send reset link';
        errorEl.textContent = 'Unable to send reset link. Please try again.';
        errorEl.style.display = 'block';
      }
    });
  </script>
</body>
</html>`;
}

function rewriteLocation(locationHeader, host) {
  try {
    const parsed = new URL(locationHeader, `https://${host}`);

    if (
      parsed.hostname === 'iam.hanzo.ai' ||
      parsed.hostname === 'iam.lux.network' ||
      parsed.hostname === 'hanzo.id' ||
      parsed.hostname === 'id.lux.network'
    ) {
      parsed.hostname = host;
    }

    return parsed.toString();
  } catch {
    return locationHeader;
  }
}

async function proxyToIam(request, url, host) {
  // RFC path normalization: map standard OAuth/OIDC paths to Casdoor's paths.
  const RFC_PATH_MAP = {
    '/oauth/token':       '/api/login/oauth/access_token',
    '/oauth/introspect':  '/api/login/oauth/introspect',
    '/oauth/revoke':      '/api/login/oauth/revoke',
    '/oauth/userinfo':    '/api/userinfo',
    '/oauth/logout':      '/login/oauth/logout',
    '/oauth/device':      '/api/login/oauth/device',
    '/oauth2/token':      '/api/login/oauth/access_token', // Legacy compat
    '/.well-known/jwks.json': '/.well-known/jwks',
  };
  const upstreamPath = RFC_PATH_MAP[url.pathname] || url.pathname;
  const iamUrl = new URL(upstreamPath + url.search, IAM_ORIGIN);

  const headers = new Headers(request.headers);
  headers.set('Host', IAM_ORIGIN_HOST);

  // IAM enforces CORS against its own host. Since this worker fronts a branded
  // domain, normalize browser origin headers for upstream IAM checks.
  if (headers.has('Origin')) {
    headers.set('Origin', IAM_ORIGIN_BASE);
  }
  if (headers.has('Referer')) {
    headers.set('Referer', `${IAM_ORIGIN_BASE}/`);
  }

  const init = {
    method: request.method,
    headers,
    redirect: 'manual',
  };

  if (request.method !== 'GET' && request.method !== 'HEAD') {
    init.body = request.body;
  }

  const upstream = await fetch(iamUrl.toString(), init);
  const outHeaders = new Headers(upstream.headers);

  const location = outHeaders.get('location');
  if (location) {
    outHeaders.set('location', rewriteLocation(location, host));
  }

  // Rewrite OIDC discovery documents to use RFC paths and public origin
  if (url.pathname.startsWith('/.well-known/')) {
    const ct = outHeaders.get('content-type') || '';
    if (ct.includes('json') || ct.includes('text')) {
      let body = await upstream.text();
      body = body.replaceAll(IAM_ORIGIN_BASE, `https://${host}`);
      body = body.replaceAll('/login/oauth/authorize', '/oauth/authorize');
      body = body.replaceAll('/api/login/oauth/access_token', '/oauth/token');
      body = body.replaceAll('/api/login/oauth/refresh_token', '/oauth/token');
      body = body.replaceAll('/api/login/oauth/introspect', '/oauth/introspect');
      body = body.replaceAll('/api/login/oauth/revoke', '/oauth/revoke');
      body = body.replaceAll('/login/oauth/logout', '/oauth/logout');
      body = body.replaceAll('/api/login/oauth/device', '/oauth/device');
      body = body.replaceAll('/api/userinfo', '/oauth/userinfo');
      return new Response(body, {
        status: upstream.status,
        statusText: upstream.statusText,
        headers: outHeaders,
      });
    }
  }

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: outHeaders,
  });
}

function redirectWithQuery(baseUrl, pathname, search, status = 302) {
  return Response.redirect(`${baseUrl}${pathname}${search}`, status);
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const { pathname } = url;
    const host = url.hostname.toLowerCase();

    if (host === 'id.lux.network' || host === 'www.lux.id') {
      return redirectWithQuery(`https://${CANONICAL_DOMAIN}`, pathname, url.search, 301);
    }

    // Auth surface pages (/login, /signup, /forget) are served directly on lux.id.
    // Only proxy IAM API paths to the auth domain; do NOT redirect browser pages.
    if (host === CANONICAL_DOMAIN && !AUTH_PATHS.has(pathname) && shouldProxyToIAM(pathname)) {
      return proxyToIam(request, url, host);
    }

    if (pathname.startsWith('/cdn/') || pathname.startsWith('/img/') || pathname === '/icon.svg') {
      const asset = serveBrandingAsset(pathname);
      if (asset) {
        return asset;
      }
    }

    if (pathname === '/callback') {
      // Check if this is a social provider callback (GitHub/Google → IAM code exchange).
      // Casdoor encodes original OAuth params as base64 in the state parameter.
      const state = url.searchParams.get('state');
      const code = url.searchParams.get('code');
      let isSocialCallback = false;
      if (state && code) {
        try {
          const decoded = atob(state);
          if (decoded.includes('provider=') || decoded.includes('application=')) {
            isSocialCallback = true;
          }
        } catch {
          // Not base64 — regular app callback
        }
      }

      if (isSocialCallback) {
        // Proxy to IAM so it can exchange the social provider code, create/link the user,
        // and redirect back to the app's redirect_uri with a Casdoor auth code.
        return proxyToIam(request, url, host);
      }

      // Regular callback — redirect to app
      const target = new URL('/auth/callback', APP_URL);
      for (const [key, value] of url.searchParams) {
        target.searchParams.set(key, value);
      }
      return Response.redirect(target.toString(), 302);
    }

    if (pathname === '/oauth/authorize' || pathname === '/login/oauth/authorize') {
      if (url.searchParams.has('provider')) {
        const provider = url.searchParams.get('provider');
        const clientId = url.searchParams.get('client_id');

        // Get social provider details (client_id, type) from IAM's public API
        let providerClientId = '';
        let providerType = '';
        try {
          const provRes = await fetch(`${IAM_ORIGIN}/api/get-provider?id=admin/${encodeURIComponent(provider)}`);
          const provData = await provRes.json();
          if (provData.data) {
            providerClientId = provData.data.clientId || '';
            providerType = provData.data.type || '';
          }
        } catch {
          // Fall through to IAM proxy
        }

        // Resolve Casdoor application name from OAuth client_id
        let appName = '';
        if (clientId) {
          const clientIdMap = {
            'lux-web3': 'app-lux-web3',
            'lux-cloud': 'lux-cloud',
            'lux-app-client-id': 'app-lux',
            'hanzo-app-client-id': 'app-hanzo',
            'hanzo-web3': 'app-hanzo-web3',
            'hanzo-cloud': 'hanzo-cloud',
          };
          const match = clientId.match(/^(?:hanzo|lux)-(.+)-client-id$/);
          appName = clientIdMap[clientId] || (match ? `app-${match[1]}` : '');

          // Validate via public API
          if (appName) {
            try {
              const appRes = await fetch(`${IAM_ORIGIN}/api/get-application?id=admin/${encodeURIComponent(appName)}`);
              const appData = await appRes.json();
              if (!appData.data) appName = '';
            } catch { /* keep guess */ }
          }
        }

        // Build Casdoor-format state: base64(original_query_string)
        const stateParams = new URLSearchParams(url.search);
        if (appName) stateParams.set('application', appName);
        stateParams.set('provider', provider);
        stateParams.set('method', 'signup');
        const stateEncoded = btoa(stateParams.toString().replace(/^\?/, ''));

        // GitHub accepts hanzo.id/callback (lenient path matching).
        // Google requires exact URI match — use iam.hanzo.ai/callback (Casdoor default).
        // Both routes ultimately reach IAM which decodes the state to find the
        // application and redirects to the app's redirect_uri.

        // Direct redirect to GitHub
        if (providerClientId && (providerType === 'GitHub' || provider === 'provider-github')) {
          const ghUrl = new URL('https://github.com/login/oauth/authorize');
          ghUrl.searchParams.set('client_id', providerClientId);
          ghUrl.searchParams.set('redirect_uri', 'https://lux.id/callback');
          ghUrl.searchParams.set('scope', 'user:email read:user');
          ghUrl.searchParams.set('response_type', 'code');
          ghUrl.searchParams.set('state', stateEncoded);
          return Response.redirect(ghUrl.toString(), 302);
        }

        // Direct redirect to Google
        // NOTE: Google requires exact redirect_uri match in Cloud Console.
        // Add https://lux.id/callback to the authorized redirect URIs for the Google OAuth client.
        if (providerClientId && (providerType === 'Google' || provider === 'provider-google')) {
          const googleUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
          googleUrl.searchParams.set('client_id', providerClientId);
          googleUrl.searchParams.set('redirect_uri', 'https://lux.id/callback');
          googleUrl.searchParams.set('scope', 'profile email');
          googleUrl.searchParams.set('response_type', 'code');
          googleUrl.searchParams.set('state', stateEncoded);
          return Response.redirect(googleUrl.toString(), 302);
        }

        // Fallback: proxy to IAM for unknown providers (web3, etc.)
        return proxyToIam(request, url, host);
      }

      const auth = normalizeAuthParams(url);
      return redirectWithQuery('https://iam.lux.network', '/login', `?${buildAuthSearchParams(auth)}`);
    }

    // Logout — clear session and redirect to login
    if (pathname === '/logout') {
      const logoutUrl = new URL('/api/logout', IAM_ORIGIN);
      logoutUrl.searchParams.set('id_token_hint', url.searchParams.get('id_token_hint') || '');
      logoutUrl.searchParams.set('post_logout_redirect_uri', `https://lux.id/login`);
      logoutUrl.searchParams.set('state', url.searchParams.get('state') || '');
      try {
        await fetch(logoutUrl.toString(), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
        });
      } catch {}
      return new Response(null, {
        status: 302,
        headers: {
          Location: '/login',
          'Set-Cookie': 'casdoor_session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; SameSite=Lax',
        },
      });
    }

    if (pathname === '/forget') {
      const auth = normalizeAuthParams(url);
      return htmlResponse(renderForgotPage(auth));
    }

    if (pathname === '/signup') {
      const auth = normalizeAuthParams(url);
      return htmlResponse(renderSignupPage(auth));
    }

    if (pathname === '/login') {
      const auth = normalizeAuthParams(url);
      return htmlResponse(renderLoginPage(auth));
    }

    if (shouldProxyToIAM(pathname)) {
      return proxyToIam(request, url, host);
    }

    // ACME challenges: pass through to origin (K8s cert-manager solver)
    if (pathname.startsWith('/.well-known/acme-challenge/')) {
      return fetch(request);
    }

    if (pathname === '/' || pathname === '') {
      return htmlResponse(renderLandingPage());
    }

    return new Response('Not Found', { status: 404 });
  },
};
