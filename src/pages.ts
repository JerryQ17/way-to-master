const pageStyle = `
  :root { color-scheme: dark; font-family: system-ui, sans-serif; background: #111827; color: #f9fafb; }
  body { max-width: 32rem; margin: 12vh auto; padding: 2rem; }
  main { display: grid; gap: 1rem; }
  input, button { box-sizing: border-box; width: 100%; padding: .75rem; border-radius: .5rem; border: 1px solid #4b5563; font: inherit; }
  input { background: #1f2937; color: inherit; }
  button { background: #f59e0b; border-color: #f59e0b; color: #111827; cursor: pointer; font-weight: 700; }
  button:disabled { cursor: wait; opacity: .6; }
  [role=status] { min-height: 1.5rem; color: #fbbf24; }
`

const clientScript = `
  const fromBase64 = (value) => {
    const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
    const binary = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4));
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  };
  const toBase64 = (value) => {
    const bytes = new Uint8Array(value);
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  };
  const credentialJSON = (credential) => ({
    id: credential.id,
    rawId: toBase64(credential.rawId),
    type: credential.type,
    response: credential.response instanceof AuthenticatorAttestationResponse
      ? { clientDataJSON: toBase64(credential.response.clientDataJSON), attestationObject: toBase64(credential.response.attestationObject) }
      : { clientDataJSON: toBase64(credential.response.clientDataJSON), authenticatorData: toBase64(credential.response.authenticatorData), signature: toBase64(credential.response.signature), userHandle: credential.response.userHandle ? toBase64(credential.response.userHandle) : undefined },
  });
  const requestJSON = (options) => ({ ...options, challenge: fromBase64(options.challenge), allowCredentials: options.allowCredentials?.map((item) => ({ ...item, id: fromBase64(item.id) })) });
  const creationJSON = (options) => ({ ...options, challenge: fromBase64(options.challenge), user: { ...options.user, id: fromBase64(options.user.id) }, excludeCredentials: options.excludeCredentials?.map((item) => ({ ...item, id: fromBase64(item.id) })) });
  const call = async (path, options) => {
    const response = await fetch(path, options);
    const body = await response.json();
    if (!response.ok) throw new Error(body.error ?? 'Request failed');
    return body;
  };
`

function page(title: string, body: string, script: string): Response {
  return new Response(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title}</title><style>${pageStyle}</style></head><body><main>${body}</main><script>${clientScript}${script}</script></body></html>`,
    {
      headers: { "Content-Type": "text/html; charset=UTF-8", "Cache-Control": "no-store" },
    },
  )
}

export function loginPage(): Response {
  return page(
    "Sign in",
    `<h1>Sign in</h1><p>Use a registered passkey to continue.</p><button id="login">Sign in with passkey</button><p role="status" id="status"></p>`,
    `document.querySelector('#login').addEventListener('click', async () => {
      const button = document.querySelector('#login'); const status = document.querySelector('#status'); button.disabled = true;
      try { const options = await call('/api/authentication/options', { method: 'POST' }); const credential = await navigator.credentials.get({ publicKey: requestJSON(options) }); await call('/api/authentication/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ response: credentialJSON(credential) }) }); location.href = '/'; }
      catch (error) { status.textContent = error.message; button.disabled = false; }
    });`,
  )
}

export function registrationPage(): Response {
  return page(
    "Register",
    `<h1>Register</h1><p>Create your account and first passkey.</p><label>Display name<input id="name" maxlength="80" autocomplete="name"></label><label>Registration token<input id="token" type="password" autocomplete="off"></label><button id="register">Register passkey</button><p role="status" id="status"></p>`,
    `document.querySelector('#register').addEventListener('click', async () => {
      const button = document.querySelector('#register'); const status = document.querySelector('#status'); const token = document.querySelector('#token').value; button.disabled = true;
      try { const headers = { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token }; const options = await call('/api/register/options', { method: 'POST', headers, body: JSON.stringify({ displayName: document.querySelector('#name').value }) }); const credential = await navigator.credentials.create({ publicKey: creationJSON(options) }); await call('/api/register/verify', { method: 'POST', headers, body: JSON.stringify({ response: credentialJSON(credential) }) }); location.href = '/'; }
      catch (error) { status.textContent = error.message; button.disabled = false; }
    });`,
  )
}
