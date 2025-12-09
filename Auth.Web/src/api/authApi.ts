export type TokenResponse = {
  access_token: string;
  expires_in: number;
  token_type: string;
  scope?: string;
  refresh_token?: string;
  refresh_token_expires_at?: string;
  id_token?: string;
};

export async function exchangeAuthorizationCode(baseUrl: string, payload: {
  code: string;
  codeVerifier: string;
  clientId: string;
  redirectUri: string;
}) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: payload.code,
    code_verifier: payload.codeVerifier,
    client_id: payload.clientId,
    redirect_uri: payload.redirectUri,
  });

  return sendTokenRequest(baseUrl, body);
}

export async function refreshAccessToken(baseUrl: string, payload: {
  refreshToken: string;
  clientId: string;
}) {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: payload.refreshToken,
    client_id: payload.clientId,
  });

  return sendTokenRequest(baseUrl, body);
}

export async function fetchUserInfo(baseUrl: string, accessToken: string) {
  const response = await fetch(joinUrl(baseUrl, '/connect/userinfo'), {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  return parseJson(response);
}

async function sendTokenRequest(baseUrl: string, body: URLSearchParams) {
  const response = await fetch(joinUrl(baseUrl, '/connect/token'), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });

  return parseJson<TokenResponse>(response);
}

async function parseJson<TResponse = Record<string, unknown>>(response: Response): Promise<TResponse> {
  const text = await response.text();
  if (!response.ok) {
    const message = text || response.statusText;
    throw new Error(message);
  }

  return text ? (JSON.parse(text) as TResponse) : ({} as TResponse);
}

function joinUrl(base: string, path: string) {
  return `${base.replace(/\/+$/, '')}${path}`;
}
