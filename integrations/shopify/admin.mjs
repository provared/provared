// The two kinds of request this server makes, and no other: the sign-in at
// the store's token address, and a query or a change at the store's Admin
// GraphQL API, both as Shopify's documentation gives them
// (shopify.dev/docs/apps/build/authentication-authorization/client-credentials-grant
// and shopify.dev/docs/api/admin-graphql).
//
// Nothing here sends a change twice. A query that is answered 401 is sent
// once more with a new access token; a change that is answered 401 is not:
// the token is dropped, the call fails, and the next call signs in again.
// Nothing is tried again after Shopify's throttling answer, an error or a
// lost connection.

/** The one version of the Admin API this server speaks. */
export const API_VERSION = '2026-10';

/** A token is renewed this long before it expires (Shopify's example: 60 seconds). */
const RENEW_BEFORE = 60_000;

/** How long Shopify is given to answer one request. */
const REQUEST_TIMEOUT = 30_000;

/** What takes the place of the client secret or an access token in any text this server writes. */
export const REMOVED = '[removed]';

/** A failure to be told to the agent as a tool error, in plain words. */
export class ToolError extends Error {}

function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/** Why a request got no answer, in a few words; never the request itself. */
function reason(e) {
  if (e?.name === 'TimeoutError' || e?.name === 'AbortError') return `no answer within ${REQUEST_TIMEOUT / 1000} seconds`;
  const code = e?.cause?.code ?? e?.code;
  return typeof code === 'string' && /^[A-Z0-9_]{1,40}$/.test(code) ? code : 'the connection failed';
}

/** At most 300 characters of text, on one line. */
function brief(text) {
  const one = String(text).replace(/\s+/g, ' ').trim();
  return one.length > 300 ? `${one.slice(0, 300)}...` : one;
}

/**
 * The store's Admin API, signed in to with the app's client ID and secret.
 * `origin` is the store's address (https://<shop>.myshopify.com). Gives
 * {graphql, scrub, scopes}.
 */
export function openAdmin({ origin, clientId, clientSecret, userAgent }) {
  let held = null;
  let expiresAt = 0;
  let scopes = null;
  let signing = null;
  const secrets = new Set([clientSecret]);

  /** Text with the client secret and every access token of this run taken out. */
  function scrub(text) {
    let out = String(text);
    for (const s of secrets) if (s) out = out.split(s).join(REMOVED);
    return out;
  }

  async function signIn() {
    let response;
    let text;
    try {
      response = await fetch(`${origin}/admin/oauth/access_token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json', 'User-Agent': userAgent },
        body: new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret }).toString(),
        redirect: 'error',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT),
      });
      text = await response.text();
    } catch (e) {
      throw new ToolError(`Could not sign in to Shopify (${reason(e)}). Nothing was asked of the store.`);
    }
    let body = null;
    try {
      body = JSON.parse(text);
    } catch {
      // Not JSON: told below.
    }
    if (response.status !== 200) {
      const said = isObject(body) && typeof body.error === 'string'
        ? `: ${brief([body.error, typeof body.error_description === 'string' ? body.error_description : ''].filter(Boolean).join(': '))}`
        : text.trim() ? `: ${brief(text)}` : '';
      throw new ToolError(`Shopify refused the sign-in (HTTP ${response.status}${said}). Check the client ID and the client secret, that the app is installed on this store, and that the app and the store belong to the same organisation. Nothing was asked of the store.`);
    }
    if (!isObject(body) || typeof body.access_token !== 'string' || body.access_token === '' || !Number.isFinite(body.expires_in) || body.expires_in <= 0) {
      throw new ToolError('Shopify answered the sign-in with something other than an access token and the time it lasts. Nothing was asked of the store.');
    }
    secrets.add(body.access_token);
    held = body.access_token;
    expiresAt = Date.now() + body.expires_in * 1000;
    scopes = typeof body.scope === 'string' ? body.scope : null;
  }

  /** An access token with more than a minute left; one sign-in at a time. */
  async function freshToken() {
    if (held !== null && Date.now() < expiresAt - RENEW_BEFORE) return held;
    held = null;
    signing ??= signIn().finally(() => {
      signing = null;
    });
    await signing;
    if (held === null) throw new ToolError('Could not sign in to Shopify. Nothing was asked of the store.');
    return held;
  }

  async function send(query, variables) {
    const used = await freshToken();
    const response = await fetch(`${origin}/admin/api/${API_VERSION}/graphql.json`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'X-Shopify-Access-Token': used, 'User-Agent': userAgent },
      body: JSON.stringify({ query, variables }),
      redirect: 'error',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT),
    });
    return { status: response.status, text: await response.text(), used };
  }

  /**
   * One query, or one change. For a change, `change` is what to do where
   * its outcome is not known ("Read the order before trying again."); a
   * change is sent once and never again.
   */
  async function graphql(query, variables, { change } = {}) {
    const notMade = change ? ' The change was not made.' : '';
    const notKnown = change ? ` Whether the change was made is not known. ${change}` : '';
    let answer;
    try {
      answer = await send(query, variables);
      if (answer.status === 401 && !change) {
        if (held === answer.used) held = null;
        answer = await send(query, variables);
      }
    } catch (e) {
      if (e instanceof ToolError) throw e;
      throw new ToolError(`Could not reach Shopify (${reason(e)}).${notKnown}`);
    }
    const { status, text } = answer;
    if (status === 401) {
      if (held === answer.used) held = null;
      throw new ToolError(change
        ? 'Shopify did not accept the access token (HTTP 401), so the change was not made. This server does not send a change a second time; it signs in again on the next call. Send the call again.'
        : 'Shopify did not accept the access token, nor a new one (HTTP 401). Check that the app is still installed on this store.');
    }
    if (status === 429) throw new ToolError(`Shopify is limiting this app's requests just now (HTTP 429).${notMade} Wait a second or more and send the call again; this server does not try again by itself.`);
    if (status === 402) throw new ToolError(`The shop is frozen (HTTP 402): its owner must pay the outstanding balance in the Shopify admin.${notMade}`);
    if (status === 423) throw new ToolError(`The shop is locked (HTTP 423).${notMade}`);
    if (status === 404) throw new ToolError(`Shopify found no such store, or no such version of the Admin API (HTTP 404). Check SHOPIFY_SHOP.${notMade}`);
    if (status >= 500) throw new ToolError(`Shopify had an error (HTTP ${status}).${notKnown}`);
    if (status !== 200) throw new ToolError(`Shopify refused the request (HTTP ${status}).${notMade}`);
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      throw new ToolError(`Shopify's answer could not be read as JSON.${notKnown}`);
    }
    if (isObject(body) && Array.isArray(body.errors) && body.errors.length > 0) {
      const codes = body.errors.map((e) => e?.extensions?.code);
      const said = brief(body.errors.map((e) => (typeof e?.message === 'string' ? e.message : '')).filter(Boolean).join('; '));
      if (codes.includes('THROTTLED')) throw new ToolError(`Shopify is limiting this app's requests just now (THROTTLED).${notMade} Wait a second or more and send the call again; this server does not try again by itself.`);
      if (codes.includes('ACCESS_DENIED')) throw new ToolError(`Shopify refused: the app does not have the access this tool needs${said ? ` (${said})` : ''}.${notMade} The access scopes this server needs are listed in its README.`);
      throw new ToolError(`Shopify answered with an error${said ? `: ${said}` : ''}.${notKnown}`);
    }
    if (!isObject(body) || !isObject(body.data)) throw new ToolError(`Shopify's answer held no data.${notKnown}`);
    return body.data;
  }

  return { graphql, scrub, scopes: () => scopes };
}
