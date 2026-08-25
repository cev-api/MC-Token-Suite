// ==UserScript==
// @name         MC Refresh Token Extractor
// @namespace    mc-token-suite
// @version      3.9.2
// @description  Like cookie_to_token.py but in your browser: uses your live login.live.com session (real browser navigation, so the session cookies are sent natively) to get the MSA refresh token, then runs the XBL -> XSTS -> Minecraft chain for a fresh MC access token. Also scans the session for an access token already stored in cookies/localStorage, and can inject pasted cookies to replace the login.live.com session.
// @author       you
// @match        https://login.live.com/*
// @match        https://www.minecraft.net/*
// @match        https://minecraft.net/*
// @connect      login.live.com
// @connect      user.auth.xboxlive.com
// @connect      xsts.auth.xboxlive.com
// @connect      api.minecraftservices.com
// @grant        GM_cookie
// @grant        GM_xmlhttpRequest
// @grant        GM_addStyle
// @grant        GM_setClipboard
// @grant        GM_setValue
// @grant        GM_getValue
// @run-at       document-idle
// ==/UserScript==

/*
 * Extracts the MSA refresh token and a fresh Minecraft access token
 * from a live login.live.com session.
 */

(function () {
    'use strict';

    // ==================== config ====================    const CLIENT_ID = '00000000402b5328'; // Minecraft Launcher v1 (desktop client)
    const REDIRECT_URI = 'https://login.live.com/oauth20_desktop.srf';
    const SCOPE = 'service::user.auth.xboxlive.com::MBI_SSL';
    const AUTHORIZE_URL = 'https://login.live.com/oauth20_authorize.srf';
    const TOKEN_URL = 'https://login.live.com/oauth20_token.srf';
    const XBL_AUTH_URL = 'https://user.auth.xboxlive.com/user/authenticate';
    const XSTS_AUTH_URL = 'https://xsts.auth.xboxlive.com/xsts/authorize';
    const MC_LOGIN_WITH_XBOX_URL = 'https://api.minecraftservices.com/authentication/login_with_xbox';
    const STORAGE_KEY = 'mc_refresh_tokens'; // saved refresh tokens
    const STORAGE_KEY_ACCESS = 'mc_access_tokens'; // saved access tokens
    const VERIFIER_KEY = 'mc_pkce_verifier'; // sessionStorage backup
    const VERIFIER_GM_KEY = 'mc_pkce_pending'; // GM storage verifier handoff
    const FLOW_KEY = 'mc_flow_active';       // sessionStorage flow marker
    const NAME_PREFIX = 'mcrt:';             // window.name popup marker
    const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

    const isTop = window.top === window.self;
    const isLive = location.hostname === 'login.live.com';

    // ==================== helpers ====================

    function b64url(bytes) {
        let bin = '';
        for (const b of bytes) bin += String.fromCharCode(b);
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    async function makePkce() {
        const verifier = b64url(crypto.getRandomValues(new Uint8Array(64)));
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
        return { verifier, challenge: b64url(new Uint8Array(digest)) };
    }

    function parseJwtPayload(payload) {
        try {
            const b64 = payload.replace(/-/g, '+').replace(/_/g, '/');
            const json = atob(b64.padEnd(b64.length + ((4 - (b64.length % 4)) % 4), '='));
            return JSON.parse(json);
        } catch (e) { return null; }
    }

    function authorizeUrl(challenge, uaid) {
        const p = new URLSearchParams({
            client_id: CLIENT_ID,
            redirect_uri: REDIRECT_URI,
            response_type: 'code',
            scope: SCOPE,
            display: 'touch',
            locale: 'en',
            lw: '1',
            fl: 'dob,easi2',
            xsup: '1',
            nopa: '2',
        });
        if (challenge) {
            p.set('code_challenge', challenge);
            p.set('code_challenge_method', 'S256');
        }
        if (uaid) p.set('uaid', uaid);
        return AUTHORIZE_URL + '?' + p.toString();
    }

    // Promisified GM_xmlhttpRequest.
    function gmRequest(opts) {
        return new Promise((resolve, reject) => {
            try {
                GM_xmlhttpRequest(Object.assign({
                    timeout: 30000,
                    onload: resolve,
                    onerror: () => reject(new Error('Network error')),
                    ontimeout: () => reject(new Error('Request timed out')),
                }, opts));
            } catch (e) { reject(e); }
        });
    }

    // uaid from the current tab's cookies.
    async function getUaid() {
        try {
            const m = document.cookie.match(/(?:^|;\s*)uaid=([^;]+)/);
            if (m) return m[1];
        } catch (e) {}
        return undefined;
    }

    // ----- session scan -----

    // Collect values from the current tab's cookies and storage.
    async function collectSessionValues() {
        const found = [];
        try {
            for (const pair of document.cookie.split(';')) {
                const i = pair.indexOf('=');
                if (i > 0) found.push({ name: pair.slice(0, i).trim(), value: pair.slice(i + 1).trim(), source: 'document.cookie' });
            }
        } catch (e) {}
        for (const store of ['localStorage', 'sessionStorage']) {
            try {
                for (let i = 0; i < window[store].length; i++) {
                    const k = window[store].key(i);
                    found.push({ name: k, value: String(window[store].getItem(k) || ''), source: store });
                }
            } catch (e) {}
        }
        return found;
    }

    // Extract JWTs from a stored value.
    function classifyJwt(value, source) {
        const matches = String(value).match(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g) || [];
        const out = [];
        for (const m of matches) {
            const payload = parseJwtPayload(m.split('.')[1]);
            if (!payload) continue;
            out.push({
                token: m,
                source,
                kind: (payload.token_type === 'Minecraft' || payload.xuid) ? 'mc' : 'other',
            });
        }
        return out;
    }

    // True if an Ew... value is a real MSA refresh token.
    function isEwRefreshToken(value) {
        const m = String(value).match(/Ew([A-Za-z0-9+\/=_\-]{100,})/);
        if (!m) return false;
        try {
            let raw = m[1].replace(/-/g, '+').replace(/_/g, '/');
            raw = raw.padEnd(raw.length + ((4 - (raw.length % 4)) % 4), '=');
            const json = JSON.parse(atob(raw));
            if (json.auth === 'XBOX' || json.xid || json.profiles || json.iss === 'authentication') return false;
            if (json.refresh_token) return true;
            if (json.token_type && /refresh/i.test(String(json.token_type))) return true;
            return /login\.live\.com/.test(JSON.stringify(json));
        } catch (e) {
            return false;
        }
    }

    // Scan the session for access and refresh tokens.
    async function findAccessTokenInSession() {
        const nameHints = ['mcaccesstoken', 'accesstoken', 'access_token', 'mcsession', 'mc_session', 'mssauth'];
        const values = await collectSessionValues();
        const result = { access: null, refresh: null };
        const consider = (kind, token, source) => {
            if (!token || result[kind]) return;
            result[kind] = { token, source };
        };
        for (const v of values) {
            const n = (v.name || '').toLowerCase();
            const s = String(v.value || '');
            // JWT access tokens, possibly in JSON blobs
            const jwt = classifyJwt(s, v.source);
            const mcJwt = jwt.find(j => j.kind === 'mc');
            const anyJwt = jwt.find(j => j.kind === 'other');
            if (mcJwt) consider('access', mcJwt.token, mcJwt.source);
            else if (anyJwt) consider('access', anyJwt.token, anyJwt.source + ' (JWT)');
            // M.-prefixed refresh tokens, or Ew... that validate as MSA
            const m2 = s.match(/M\.[A-Za-z0-9_\-\.\+\/=]{150,}/);
            if (m2) {
                consider('refresh', m2[0], v.source);
            } else if (isEwRefreshToken(s)) {
                const ew = s.match(/Ew[A-Za-z0-9+\/=_\-]{100,}/);
                if (ew) consider('refresh', ew[0], v.source);
            }
            // Storage entries named like an access token
            if (n && nameHints.some(h => n.includes(h)) && s && s.length > 50 && !result.access) {
                consider('access', s, v.source + ' (' + v.name + ')');
            }
        }
        return result;
    }

    // ----- OAuth exchange -----

    // Silent authorize fetch; returns the code or null.
    async function silentAuthorize(challenge, uaid) {
        const resp = await fetch(authorizeUrl(challenge, uaid), {
            credentials: 'include',
            redirect: 'follow',
        });
        return new URL(resp.url).searchParams.get('code') || null;
    }

    // Exchange the code for tokens via GM_xmlhttpRequest.
    async function exchangeCode(theCode, verifier) {
        const body = new URLSearchParams({
            client_id: CLIENT_ID,
            code: theCode,
            grant_type: 'authorization_code',
            redirect_uri: REDIRECT_URI,
        });
        if (verifier) body.set('code_verifier', verifier);
        const resp = await gmRequest({
            method: 'POST',
            url: TOKEN_URL,
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': UA },
            data: body.toString(),
        });
        let data = {};
        try { data = JSON.parse(resp.responseText); } catch (e) {}
        // Access token is required.
        if (resp.status !== 200 || !data.access_token) {
            throw new Error('Token exchange failed: ' + (data.error_description || data.error || ('HTTP ' + resp.status)));
        }
        return data; // { access_token, refresh_token?, expires_in, scope, token_type }
    }

    // ----- MSA -> XBL -> XSTS -> Minecraft chain -----

    async function xblAuthenticate(msaToken) {
        const ticket = msaToken.startsWith('eyJ') ? 'd=' + msaToken
            : (msaToken.startsWith('t=') || msaToken.startsWith('d=') ? msaToken : 't=' + msaToken);
        const resp = await gmRequest({
            method: 'POST',
            url: XBL_AUTH_URL,
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'User-Agent': UA },
            data: JSON.stringify({
                Properties: { AuthMethod: 'RPS', SiteName: 'user.auth.xboxlive.com', RpsTicket: ticket },
                RelyingParty: 'http://auth.xboxlive.com',
                TokenType: 'JWT',
            }),
        });
        const data = JSON.parse(resp.responseText || '{}');
        if (resp.status !== 200 || !data.Token) {
            throw new Error('XBL authenticate failed' + (data.XErr ? ' (XErr ' + data.XErr + ')' : ' (HTTP ' + resp.status + ')'));
        }
        return { token: data.Token, uhs: data.DisplayClaims.xui[0].uhs };
    }

    async function xstsAuthorize(xblToken) {
        const resp = await gmRequest({
            method: 'POST',
            url: XSTS_AUTH_URL,
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'User-Agent': UA },
            data: JSON.stringify({
                Properties: { SandboxId: 'RETAIL', UserTokens: [xblToken] },
                RelyingParty: 'rp://api.minecraftservices.com/',
                TokenType: 'JWT',
            }),
        });
        const data = JSON.parse(resp.responseText || '{}');
        if (resp.status !== 200 || !data.Token) {
            const err = data.XErr;
            let msg = 'XSTS authorize failed (XErr ' + err + ')';
            if (err === 2148916233) msg += ' - this Microsoft account has no Xbox profile';
            else if (err === 2148916238) msg += ' - account under 18 (parental consent required)';
            throw new Error(msg);
        }
        return { token: data.Token, uhs: data.DisplayClaims.xui[0].uhs };
    }

    async function mcLoginWithXbox(xstsToken, uhs) {
        const resp = await gmRequest({
            method: 'POST',
            url: MC_LOGIN_WITH_XBOX_URL,
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json', 'User-Agent': UA },
            data: JSON.stringify({ identityToken: 'XBL3.0 x=' + uhs + ';' + xstsToken }),
        });
        const data = JSON.parse(resp.responseText || '{}');
        if (resp.status !== 200 || !data.access_token) {
            throw new Error('Minecraft login_with_xbox failed (HTTP ' + resp.status + ')');
        }
        return data; // { access_token, username, expires_in }
    }

    // ==================== storage / clipboard ====================

    function loadTokens() {
        try {
            return (GM_getValue(STORAGE_KEY, '') || '')
                .split('\n').map(s => s.trim()).filter(Boolean);
        } catch (e) { return []; }
    }

    function storeTokens(lines) {
        try { GM_setValue(STORAGE_KEY, lines.join('\n')); } catch (e) {}
    }

    function pushToken(tok) {
        const lines = loadTokens();
        if (tok && !lines.includes(tok)) {
            lines.push(tok);
            storeTokens(lines);
        }
        return lines;
    }

    function loadAccessTokens() {
        try {
            return (GM_getValue(STORAGE_KEY_ACCESS, '') || '')
                .split('\n').map(s => s.trim()).filter(Boolean);
        } catch (e) { return []; }
    }

    function storeAccessTokens(lines) {
        try { GM_setValue(STORAGE_KEY_ACCESS, lines.join('\n')); } catch (e) {}
    }

    function pushAccessToken(tok) {
        const lines = loadAccessTokens();
        if (tok && !lines.includes(tok)) {
            lines.push(tok);
            storeAccessTokens(lines);
        }
        return lines;
    }

    async function copyText(text) {
        try { if (typeof GM_setClipboard === 'function') { GM_setClipboard(text); return true; } } catch (e) {}
        try { await navigator.clipboard.writeText(text); return true; } catch (e) {}
        try {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            const ok = document.execCommand('copy');
            ta.remove();
            return ok;
        } catch (e) { return false; }
    }

    // Copy with button feedback.
    async function copyWithFeedback(btn, text) {
        const ok = await copyText(text);
        const old = btn.textContent;
        btn.textContent = ok ? '✓ Copied' : 'Copy failed';
        btn.classList.add('copied');
        setTimeout(() => { btn.textContent = old; btn.classList.remove('copied'); }, 1500);
    }

    // ==================== cookie injection (GM_cookie) ====================

    function gmCookieList(url) {
        return new Promise((resolve) => {
            if (typeof GM_cookie === 'undefined' || !GM_cookie.list) { resolve([]); return; }
            let done = false;
            const finish = (v) => { if (!done) { done = true; resolve(v || []); } };
            try {
                const out = GM_cookie.list({ url }, finish);
                if (out && typeof out.then === 'function') out.then(finish).catch(() => finish([]));
            } catch (e) { finish([]); }
        });
    }

    function gmCookieSet(opts) {
        return new Promise((resolve) => {
            if (typeof GM_cookie === 'undefined' || !GM_cookie.set) { resolve(false); return; }
            let done = false;
            const finish = (ok) => { if (!done) { done = true; resolve(!!ok); } };
            try {
                const out = GM_cookie.set(opts, (err) => finish(!err));
                if (out && typeof out.then === 'function') out.then(() => finish(true)).catch(() => finish(false));
            } catch (e) { finish(false); }
        });
    }

    function gmCookieDelete(url, name) {
        return new Promise((resolve) => {
            if (typeof GM_cookie === 'undefined' || !GM_cookie.delete) { resolve(false); return; }
            let done = false;
            const finish = () => { if (!done) { done = true; resolve(true); } };
            try {
                const out = GM_cookie.delete({ url, name }, finish);
                if (out && typeof out.then === 'function') out.then(finish).catch(finish);
            } catch (e) { finish(); }
        });
    }

    // Parse Netscape .txt lines or name=value pairs.
    function parseCookiesInput(text) {
        const cookies = [];
        for (const line of String(text || '').split(/\r?\n/)) {
            const t = line.trim();
            if (!t || t.startsWith('#')) continue;
            const parts = t.split('\t');
            if (parts.length >= 7) {
                const [domain, flag, path, secure, expires, name, value] = parts;
                if (name && value != null) {
                    cookies.push({
                        name, value,
                        domain: domain || undefined,
                        path: path || '/',
                        secure: secure === 'TRUE',
                        httpOnly: flag === 'TRUE',
                        expires: Number(expires) > 0 ? Number(expires) : undefined,
                    });
                }
                continue;
            }
            const m = t.match(/^([^=;\s]+)\s*=\s*(.*)$/);
            if (m && m[1] && m[2] != null) cookies.push({ name: m[1], value: m[2] });
        }
        return cookies;
    }

    // Replace the login.live.com session with the pasted cookies.
    async function applyCookies() {
        if (typeof GM_cookie === 'undefined') {
            setStatus('❌ Cookie injection needs Tampermonkey (GM_cookie).', 'err');
            return;
        }
        const cookies = parseCookiesInput(panel.querySelector('#mcrte-cookies').value);
        if (!cookies.length) {
            setStatus('⚠️ No cookies parsed - paste Netscape .txt lines or name=value pairs.', 'err');
            return;
        }
        const url = 'https://login.live.com/';
        setStatus('Clearing existing login.live.com cookies…', null);
        const existing = await gmCookieList(url);
        for (const c of existing) {
            if (c && c.name) await gmCookieDelete(url, c.name);
        }
        setStatus(`Setting ${cookies.length} cookie(s)…`, null);
        let okCount = 0;
        for (const c of cookies) {
            const opts = {
                url,
                name: c.name,
                value: c.value,
                path: c.path || '/',
            };
            if (c.domain) opts.domain = c.domain;
            if (c.secure) opts.secure = true;
            if (c.httpOnly) opts.httpOnly = true;
            if (c.expires) opts.expirationDate = c.expires;
            if (await gmCookieSet(opts)) okCount++;
        }
        try { localStorage.setItem('mcrt_cookies_input', panel.querySelector('#mcrte-cookies').value); } catch (e) {}
        setStatus(okCount
            ? `✅ ${okCount}/${cookies.length} cookie(s) applied - click Extract Tokens.`
            : `⚠️ 0/${cookies.length} applied. In Tampermonkey enable the cookie API for this script (script settings → "Allow access to cookie API").`,
            okCount ? 'ok' : 'err');
    }

    async function clearLiveCookies() {
        if (typeof GM_cookie === 'undefined') {
            setStatus('❌ Needs Tampermonkey (GM_cookie).', 'err');
            return;
        }
        const url = 'https://login.live.com/';
        const existing = await gmCookieList(url);
        for (const c of existing) {
            if (c && c.name) await gmCookieDelete(url, c.name);
        }
        setStatus(`🧹 Removed ${existing.length} login.live.com cookie(s).`, 'ok');
    }

    // ==================== panel UI ====================
    GM_addStyle(`
        #mcrte-panel {
            position: fixed; z-index: 2147483647; top: 16px; right: 16px; width: 400px;
            font: 13px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
            color: #e8eaed; background: #202124; border: 1px solid #3c4043;
            border-radius: 10px; box-shadow: 0 6px 24px rgba(0,0,0,.45);
            overflow: hidden; text-align: left;
        }
        #mcrte-panel *, #mcrte-panel *::before, #mcrte-panel *::after { box-sizing: border-box; }
        #mcrte-panel .mcrte-head {
            display: flex; align-items: center; justify-content: space-between; gap: 8px;
            padding: 8px 12px; background: #2a2d31; cursor: move; user-select: none;
        }
        #mcrte-panel .mcrte-title { font-weight: 600; font-size: 12.5px; }
        #mcrte-panel .mcrte-close { cursor: pointer; opacity: .7; padding: 0 4px; font-size: 13px; }
        #mcrte-panel .mcrte-close:hover { opacity: 1; }
        #mcrte-panel .mcrte-body { padding: 12px; }
        #mcrte-panel .mcrte-status { margin-bottom: 10px; min-height: 16px; color: #bdc1c6; }
        #mcrte-panel .mcrte-status.err { color: #f28b82; }
        #mcrte-panel .mcrte-status.ok { color: #81c995; }
        #mcrte-panel .mcrte-btn {
            display: inline-block; width: 100%; padding: 8px 10px; border: 0; border-radius: 6px;
            background: #3b6ef6; color: #fff; font: inherit; font-weight: 600; cursor: pointer;
        }
        #mcrte-panel .mcrte-btn:hover { background: #4d7bfb; }
        #mcrte-panel .mcrte-btn.small { width: auto; padding: 4px 10px; font-weight: 500; }
        #mcrte-panel .mcrte-btn.danger { background: #5f6368; }
        #mcrte-panel .mcrte-btn.danger:hover { background: #8f3b3b; }
        #mcrte-panel .mcrte-btn.copied { background: #188038; }
        #mcrte-panel .mcrte-label { margin: 12px 0 4px; color: #bdc1c6; }
        #mcrte-panel .mcrte-note { margin-top: 4px; color: #9aa0a6; font-size: 11.5px; }
        #mcrte-panel .mcrte-token {
            width: 100%; resize: vertical; min-height: 60px; padding: 6px;
            border: 1px solid #3c4043; border-radius: 6px; background: #17181a;
            color: #9fc7ff; font: 11px/1.4 Consolas, Menlo, monospace; word-break: break-all;
        }
        #mcrte-panel .mcrte-row { display: flex; gap: 6px; margin-top: 6px; }
        #mcrte-panel .mcrte-details { margin-top: 10px; }
        #mcrte-panel .mcrte-details summary { cursor: pointer; color: #9aa0a6; }
        #mcrte-panel .mcrte-saved { margin-top: 10px; color: #9aa0a6; font-size: 11.5px; }
        #mcrte-panel .mcrte-footer { margin-top: 10px; padding-top: 8px; border-top: 1px solid #3c4043; }
    `);

    let panel = null;

    function buildPanel() {
        if (panel || !isTop) return;
        panel = document.createElement('div');
        panel.id = 'mcrte-panel';
        panel.innerHTML = `
            <div class="mcrte-head">
                <span class="mcrte-title">🟢 MC Refresh Token Extractor</span>
                <span class="mcrte-close" title="Hide">✕</span>
            </div>
            <div class="mcrte-body">
                <div class="mcrte-status" id="mcrte-status">Ready.</div>
                <button class="mcrte-btn" id="mcrte-extract">Extract Tokens</button>

                <div class="mcrte-label">Refresh token</div>
                <textarea class="mcrte-token" id="mcrte-refresh" rows="2" readonly spellcheck="false" placeholder="run the extractor…"></textarea>
                <div class="mcrte-row">
                    <button class="mcrte-btn small" id="mcrte-copy">Copy</button>
                    <button class="mcrte-btn small danger" id="mcrte-clear-refresh" title="Clear this box - only you">Clear</button>
                </div>

                <div class="mcrte-label">Access token</div>
                <textarea class="mcrte-token" id="mcrte-access" rows="2" readonly spellcheck="false" placeholder="scanning your session…"></textarea>
                <div class="mcrte-note" id="mcrte-access-note"></div>
                <div class="mcrte-row">
                    <button class="mcrte-btn small" id="mcrte-copy-access">Copy</button>
                    <button class="mcrte-btn small danger" id="mcrte-clear-access" title="Clear this box - only you">Clear</button>
                </div>

                <details class="mcrte-details" id="mcrte-cookiebox">
                    <summary>Inject cookies (replace login.live.com session)</summary>
                    <textarea class="mcrte-token" id="mcrte-cookies" rows="4" spellcheck="false" placeholder="Paste Netscape .txt cookie lines or name=value pairs&#10;for login.live.com - this replaces the current session."></textarea>
                    <div class="mcrte-row">
                        <button class="mcrte-btn small" id="mcrte-apply-cookies">Apply cookies</button>
                        <button class="mcrte-btn small danger" id="mcrte-clear-cookies">Clear cookies</button>
                    </div>
                    <div class="mcrte-note">Deletes the current login.live.com session first, then sets the pasted cookies (incl. HttpOnly). Runs in the default cookie store - use a normal tab if your tab group is isolated.</div>
                </details>

                <div class="mcrte-footer">
                    <div class="mcrte-saved" id="mcrte-saved"></div>
                    <details class="mcrte-details" id="mcrte-history" hidden>
                        <summary>View all saved refresh tokens</summary>
                        <textarea class="mcrte-token" id="mcrte-all" rows="3" readonly spellcheck="false"></textarea>
                        <div class="mcrte-row">
                            <button class="mcrte-btn small" id="mcrte-copy-all">Copy all</button>
                            <button class="mcrte-btn small danger" id="mcrte-clear-saved">Clear saved</button>
                        </div>
                    </details>
                </div>
            </div>`;
        document.documentElement.appendChild(panel);

        // drag
        const head = panel.querySelector('.mcrte-head');
        let dragging = false, offX = 0, offY = 0;
        head.addEventListener('pointerdown', (e) => {
            if (e.target.closest('.mcrte-close')) return;
            dragging = true;
            const r = panel.getBoundingClientRect();
            offX = e.clientX - r.left;
            offY = e.clientY - r.top;
            head.setPointerCapture(e.pointerId);
        });
        head.addEventListener('pointermove', (e) => {
            if (!dragging) return;
            panel.style.right = 'auto';
            panel.style.left = Math.max(0, e.clientX - offX) + 'px';
            panel.style.top = Math.max(0, e.clientY - offY) + 'px';
        });
        head.addEventListener('pointerup', () => { dragging = false; });

        // events
        panel.querySelector('.mcrte-close').addEventListener('click', () => panel.remove());
        panel.querySelector('#mcrte-extract').addEventListener('click', startFlow);
        panel.querySelector('#mcrte-copy').addEventListener('click', (ev) =>
            copyWithFeedback(ev.currentTarget, panel.querySelector('#mcrte-refresh').value));
        panel.querySelector('#mcrte-copy-access').addEventListener('click', (ev) =>
            copyWithFeedback(ev.currentTarget, panel.querySelector('#mcrte-access').value));
        panel.querySelector('#mcrte-clear-refresh').addEventListener('click', () => {
            panel.querySelector('#mcrte-refresh').value = '';
            try { localStorage.removeItem('mcrt_result'); } catch (e) {}
        });
        panel.querySelector('#mcrte-clear-access').addEventListener('click', () => {
            panel.querySelector('#mcrte-access').value = '';
            panel.querySelector('#mcrte-access-note').textContent = '';
            try { localStorage.removeItem('mcrt_result'); } catch (e) {}
        });
        panel.querySelector('#mcrte-copy-all').addEventListener('click', (ev) =>
            copyWithFeedback(ev.currentTarget, loadTokens().join('\n')));
        panel.querySelector('#mcrte-clear-saved').addEventListener('click', () => {
            if (!confirm('Clear all saved tokens? This cannot be undone.')) return;
            try { GM_setValue(STORAGE_KEY, ''); } catch (e) {}
            try { GM_setValue(STORAGE_KEY_ACCESS, ''); } catch (e) {}
            updateSaved([]);
            setStatus('🗑️ Saved tokens cleared.', 'ok');
        });
        panel.querySelector('#mcrte-apply-cookies').addEventListener('click', applyCookies);
        panel.querySelector('#mcrte-clear-cookies').addEventListener('click', clearLiveCookies);
        try {
            const prev = localStorage.getItem('mcrt_cookies_input');
            if (prev) panel.querySelector('#mcrte-cookies').value = prev;
        } catch (e) {}

        updateSaved(loadTokens());
    }

    function setStatus(text, cls) {
        if (!panel) return;
        const el = panel.querySelector('#mcrte-status');
        el.textContent = text;
        el.className = 'mcrte-status' + (cls ? ' ' + cls : '');
    }

    function updateSaved(lines) {
        if (!panel) return;
        const n = lines.length;
        panel.querySelector('#mcrte-saved').textContent =
            n + (n === 1 ? ' refresh token saved' : ' refresh tokens saved') + ' in script storage.';
        const hist = panel.querySelector('#mcrte-history');
        hist.hidden = n === 0;
        panel.querySelector('#mcrte-all').value = lines.join('\n');
    }

    // ==================== flow ====================
    function showResult(refresh, access, lines, note) {
        if (!panel) return;
        if (refresh) panel.querySelector('#mcrte-refresh').value = refresh;
        if (access) panel.querySelector('#mcrte-access').value = access;
        if (note) panel.querySelector('#mcrte-access-note').textContent = note;
        updateSaved(lines);
    }

    async function finishSuccess(data, flowId) {
        const refresh = data.refresh_token || '';
        const msaAccess = data.access_token || '';
        const lines = pushToken(refresh);
        let mc = null, note = '';
        if (msaAccess) {
            setStatus('Exchanging MSA → Minecraft access token…', null);
            try {
                const xbl = await xblAuthenticate(msaAccess);
                const xsts = await xstsAuthorize(xbl.token);
                const login = await mcLoginWithXbox(xsts.token, xsts.uhs);
                mc = login.access_token;
            } catch (e) {
                note = 'Access token obtained, but the Minecraft chain failed: ' + e.message;
            }
        }
        const finalAccess = mc || msaAccess || '';
        if (finalAccess) pushAccessToken(finalAccess);
        showResult(refresh, finalAccess, lines, note);
        if (refresh) {
            setStatus('✅ Refresh token extracted & copied to clipboard.', 'ok');
            copyText(refresh);
        } else if (mc) {
            setStatus('⚠️ No refresh token issued by Microsoft this time, but the Minecraft access token is ready for token.txt.', 'ok');
        } else if (msaAccess) {
            setStatus('⚠️ No refresh token issued; MSA access token shown (not a Minecraft token).', 'ok');
        }
        try { history.replaceState(null, '', '/oauth20_desktop.srf'); } catch (e) {}
        try { localStorage.setItem('mcrt_done', '1'); } catch (e) {}
        // Persist for this page's reload.
        try {
            localStorage.setItem('mcrt_result', JSON.stringify({ refresh: refresh, access: mc || msaAccess || '' }));
        } catch (e) {}
        if (window.opener) {
            // Deliver the result to the opener.
            const payload = { source: 'mcrt', refresh: refresh, access: mc || msaAccess || '', note: note };
            let posted = false;
            for (let i = 0; i < 5; i++) {
                try {
                    window.opener.postMessage(payload, '*');
                    posted = true;
                    break;
                } catch (e) {
                    await new Promise(r => setTimeout(r, 400));
                }
            }
            // Also write it to the opener's window.name.
            try {
                window.opener.name = 'mcrt_result:' + JSON.stringify({
                    refresh: refresh,
                    access: mc || msaAccess || '',
                    note: note,
                });
            } catch (e) {}
            try {
                window.name = 'mcrt_result:' + JSON.stringify({
                    refresh: refresh,
                    access: mc || msaAccess || '',
                    note: note,
                });
            } catch (e) {}
            // Also save a GM storage payload for the opener.
            try {
                GM_setValue('mcrt_deliver', JSON.stringify({
                    refresh: refresh,
                    access: mc || msaAccess || '',
                    note: note,
                    ts: Date.now(),
                    flowId: flowId || '',
                }));
            } catch (e) {}
            setStatus('✅ Tokens captured - sent to the tab you came from. Closing…', 'ok');
            if (refresh) copyText(refresh);
            const closeIt = () => { try { window.close(); } catch (e) {} };
            if (posted) {
                setTimeout(closeIt, 1500);
            } else {
                // Close on ack or after 5s.
                setTimeout(closeIt, 5000);
                let n = 0;
                const iv = setInterval(() => {
                    n++;
                    let name = '';
                    try { name = window.name || ''; } catch (e) {}
                    if (name === 'mcrt_ack' || n > 25) { clearInterval(iv); closeIt(); }
                }, 200);
            }
        } else if (refresh) {
            setStatus('✅ Tokens captured & copied to clipboard. You can close this tab.', 'ok');
        }
    }

    async function handleDesktopRedirect(theCode) {
        const oauthError = new URL(location.href).searchParams.get('error');
        if (oauthError) {
            guideToAccessToken('OAuth error: ' + oauthError + ' - the refresh flow was rejected.');
            return;
        }
        let verifier = null, flowId = '';
        // GM storage verifier.
        try {
            const raw = GM_getValue(VERIFIER_GM_KEY, '');
            GM_setValue(VERIFIER_GM_KEY, '');
            if (raw) {
                const rec = JSON.parse(raw);
                if (rec && rec.verifier && (Date.now() - (rec.ts || 0)) < 10 * 60 * 1000) {
                    verifier = rec.verifier;
                    flowId = rec.flowId || '';
                }
            }
        } catch (e) {}
        // window.name / sessionStorage backups.
        if (!verifier && typeof window.name === 'string' && window.name.startsWith(NAME_PREFIX)) {
            const parts = window.name.slice(NAME_PREFIX.length).split('::');
            verifier = parts[0] || null;
            flowId = parts[1] || '';
            try { window.name = ''; } catch (e) {}
        }
        if (!verifier) {
            try {
                verifier = sessionStorage.getItem(VERIFIER_KEY) || null;
                if (verifier) sessionStorage.removeItem(VERIFIER_KEY);
                sessionStorage.removeItem(FLOW_KEY);
            } catch (e) {}
        }
        setStatus('Exchanging code for tokens…', null);
        try {
            const data = await exchangeCode(theCode, verifier);
            await finishSuccess(data, flowId);
        } catch (e) {
            guideToAccessToken(e.message);
        }
    }
    // Apply a received result to the panel.
    function applyResult(res) {
        if (!res || !panel) return;
        showResult(res.refresh, res.access, loadTokens(), res.note || '');
        setStatus('✅ Refresh token received from the popup - copied to clipboard.', 'ok');
        if (res.refresh) copyText(res.refresh);
        try {
            localStorage.setItem('mcrt_result', JSON.stringify({ refresh: res.refresh || '', access: res.access || '' }));
        } catch (e) {}
        try { GM_setValue('mcrt_deliver', ''); } catch (e) {}
        try { sessionStorage.removeItem('mcrt_flowid'); } catch (e) {}
    }

    // Pick up a GM storage delivery for this tab's flow.
    function tryPickupDeliver() {
        try {
            const raw = GM_getValue('mcrt_deliver', '');
            if (!raw) return false;
            const rec = JSON.parse(raw);
            const myFlow = sessionStorage.getItem('mcrt_flowid') || '';
            if (!rec || !rec.refresh) { GM_setValue('mcrt_deliver', ''); return false; }
            if ((Date.now() - (rec.ts || 0)) > 600000) { GM_setValue('mcrt_deliver', ''); return false; }
            // Only consume this tab's flow.
            if (rec.flowId && rec.flowId !== myFlow) return false;
            if (!rec.flowId && !myFlow) return false;
            GM_setValue('mcrt_deliver', '');
            applyResult(rec);
            return true;
        } catch (e) { return false; }
    }

    // Poll for the popup result.
    function startResultPolling(win) {
        let done = false;
        const apply = () => {
            if (done) return;
            // This tab's own window.name result.
            let name = '';
            try { name = window.name || ''; } catch (e) {}
            if (name.startsWith('mcrt_result:')) {
                done = true;
                try { window.name = ''; } catch (e) {}
                try { applyResult(JSON.parse(name.slice('mcrt_result:'.length))); } catch (e) {}
                return;
            }
            // GM storage fallback.
            if (tryPickupDeliver()) done = true;
        };
        const poll = setInterval(apply, 400);
        setTimeout(() => { clearInterval(poll); done = true; }, 120000);
        window.addEventListener('focus', apply);
    }

    async function startFlow() {
        setStatus('Preparing PKCE…', null);
        try {
            const { verifier, challenge } = await makePkce();
            // Tag the flow for this tab.
            let flowId = '';
            try {
                flowId = crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + '-' + Math.random().toString(36).slice(2);
                sessionStorage.setItem('mcrt_flowid', flowId);
            } catch (e) {}
            // Hand the verifier to the popup via GM storage.
            try { GM_setValue(VERIFIER_GM_KEY, JSON.stringify({ verifier, ts: Date.now(), flowId })); } catch (e) {}

            if (isLive) {
                const uaid = await getUaid();
                // Try a silent fetch first.
                setStatus('Contacting login.live.com…', null);
                try {
                    const code = await silentAuthorize(challenge, uaid);
                    if (code) {
                        const data = await exchangeCode(code, verifier);
                        await finishSuccess(data);
                        return;
                    }
                } catch (e) {}
                // Fall back to real navigation.
                try {
                    sessionStorage.setItem(VERIFIER_KEY, verifier);
                    sessionStorage.setItem(FLOW_KEY, String(Date.now()));
                } catch (e) {}
                setStatus('Opening login.live.com - complete sign-in / account pick if shown; the token is captured automatically afterwards.', null);
                location.href = authorizeUrl(challenge, uaid);
                return;
            }

            // Open the flow in a popup.
            const win = window.open('', '_blank');
            if (!win) {
                // Save the verifier for the same-tab flow.
                try {
                    sessionStorage.setItem(VERIFIER_KEY, verifier);
                    sessionStorage.setItem(FLOW_KEY, String(Date.now()));
                } catch (e) {}
                setStatus('Popup blocked - navigating this tab instead.', null);
                location.href = authorizeUrl(challenge);
                return;
            }
            try { window.name = ''; } catch (e) {}
            win.name = NAME_PREFIX + verifier + '::' + flowId;
            win.location.href = authorizeUrl(challenge);
            startResultPolling(win);
            setStatus('Opened login.live.com in a new tab. If it shows a sign-in page your Microsoft session has expired - sign in there once; the token is captured automatically afterwards.', 'ok');
        } catch (e) {
            guideToAccessToken(e.message);
        }
    }

    // Fill empty boxes from this tab's session.
    async function scanAccessToken() {
        if (!panel) return;
        // Restore the last result in this tab.
        try {
            const saved = JSON.parse(localStorage.getItem('mcrt_result') || 'null');
            if (saved) {
                if (saved.refresh && !panel.querySelector('#mcrte-refresh').value) {
                    panel.querySelector('#mcrte-refresh').value = saved.refresh;
                }
                if (saved.access && !panel.querySelector('#mcrte-access').value) {
                    panel.querySelector('#mcrte-access').value = saved.access;
                    panel.querySelector('#mcrte-access-note').textContent = 'From your last extraction in this tab.';
                }
            }
        } catch (e) {}
        try {
            const found = await findAccessTokenInSession();
            if (!found) return;
            const parts = [];
            if (found.refresh && !panel.querySelector('#mcrte-refresh').value) {
                panel.querySelector('#mcrte-refresh').value = found.refresh.token;
                pushToken(found.refresh.token);
                parts.push('refresh ' + found.refresh.source);
            }
            if (found.access && !panel.querySelector('#mcrte-access').value) {
                panel.querySelector('#mcrte-access').value = found.access.token;
                pushAccessToken(found.access.token);
                panel.querySelector('#mcrte-access-note').textContent = 'Found in this tab: ' + found.access.source + '.';
                parts.push('access ' + found.access.source);
            }
            if (parts.length) {
                setStatus('🔑 Found in this tab: ' + parts.join('; ') + '.', 'ok');
            }
        } catch (e) {}
        updateSaved(loadTokens());
    }

    // OAuth failed - show any tokens still in the session.
    async function guideToAccessToken(fallbackMsg) {
        try {
            const found = await findAccessTokenInSession();
            if (found && panel && (found.access || found.refresh)) {
                // Only fill empty boxes - never overwrite what is shown.
                if (found.access && !panel.querySelector('#mcrte-access').value) {
                    panel.querySelector('#mcrte-access').value = found.access.token;
                    panel.querySelector('#mcrte-access-note').textContent = 'From session: ' + found.access.source + ' - still valid for token.txt.';
                }
                if (found.refresh && !panel.querySelector('#mcrte-refresh').value) {
                    panel.querySelector('#mcrte-refresh').value = found.refresh.token;
                }
                setStatus('⚠️ ' + fallbackMsg + ' Tokens recovered from your session are in the boxes below (access → token.txt).', 'ok');
            } else {
                setStatus('❌ ' + fallbackMsg, 'err');
            }
        } catch (e) {
            setStatus('❌ ' + fallbackMsg, 'err');
        }
    }

    // ==================== init ====================

    function init() {
        buildPanel();
        scanAccessToken();

        // Pick up a delivered result (opener only).
        if (!(isLive && location.pathname.includes('oauth20_desktop.srf'))) {
            tryPickupDeliver();
            // Keep polling while a flow is in flight.
            let inFlight = false;
            try { inFlight = !!sessionStorage.getItem('mcrt_flowid'); } catch (e) {}
            if (inFlight) startResultPolling(null);
        }

        // Receive the popup result.
        window.addEventListener('message', (ev) => {
            if (!ev.data || ev.data.source !== 'mcrt') return;
            if (ev.origin !== 'https://login.live.com') return;
            showResult(ev.data.refresh, ev.data.access, loadTokens(), ev.data.note || '');
            setStatus('✅ Refresh token received from the popup - copied to clipboard.', 'ok');
            if (ev.data.refresh) copyText(ev.data.refresh);
            try {
                localStorage.setItem('mcrt_result', JSON.stringify({ refresh: ev.data.refresh || '', access: ev.data.access || '' }));
            } catch (e) {}
        });

        const isDesktopRedirect = isLive && location.pathname.includes('oauth20_desktop.srf');
        const code = new URL(location.href).searchParams.get('code');
        if (isDesktopRedirect && code) {
            handleDesktopRedirect(code);
            return;
        }
        // Re-show tokens and close after a reload.
        if (isDesktopRedirect) {
            try {
                if (localStorage.getItem('mcrt_done')) {
                    const saved = JSON.parse(localStorage.getItem('mcrt_result') || 'null');
                    if (saved) {
                        if (saved.refresh && !panel.querySelector('#mcrte-refresh').value) {
                            panel.querySelector('#mcrte-refresh').value = saved.refresh;
                        }
                        if (saved.access && !panel.querySelector('#mcrte-access').value) {
                            panel.querySelector('#mcrte-access').value = saved.access;
                        }
                    }
                    if (window.opener) {
                        setStatus('✅ Done - tokens sent back. Closing…', 'ok');
                        setTimeout(() => { try { window.close(); } catch (e) {} }, 800);
                    } else {
                        setStatus('✅ Done - tokens captured. You can close this tab.', 'ok');
                    }
                }
            } catch (e) {}
        }
        // A flow is waiting for interaction.
        if (isLive && !isDesktopRedirect) {
            let inProgress = false;
            try {
                const t = parseInt(sessionStorage.getItem(FLOW_KEY), 10);
                inProgress = !!t && (Date.now() - t) < 10 * 60 * 1000;
            } catch (e) {}
            if (!inProgress && typeof window.name === 'string' && window.name.startsWith(NAME_PREFIX)) inProgress = true;
            if (inProgress) {
                setStatus('⏳ Microsoft sign-in / account picker - complete it on this page. The token is captured automatically when the flow finishes.', null);
            }
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
