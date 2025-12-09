import { FormEvent, useEffect, useMemo, useState } from 'react';
import { exchangeAuthorizationCode, fetchUserInfo, refreshAccessToken, TokenResponse } from './api/authApi';
import { generatePkcePair, generateState } from './utils/pkce';

type CallbackInfo = {
  parameters: Record<string, string>;
  code?: string;
  state?: string;
  error?: string;
  error_description?: string;
};

type UserInfo = Record<string, unknown>;

const defaultBaseUrl = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080';

export default function App() {
  const isBrowser = typeof window !== 'undefined';
  const defaultRedirectUri = isBrowser ? `${window.location.origin}/callback` : 'http://localhost:4173/callback';

  const [baseUrl, setBaseUrl] = useState(defaultBaseUrl);
  const [clientId, setClientId] = useState('spa-localhost');
  const [redirectUri, setRedirectUri] = useState(defaultRedirectUri);
  const [scopeText, setScopeText] = useState('openid profile offline_access');
  const [isRedirecting, setIsRedirecting] = useState(false);
  const [isExchanging, setIsExchanging] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isLoadingUserInfo, setIsLoadingUserInfo] = useState(false);
  const [lastAuthorizeUrl, setLastAuthorizeUrl] = useState<string>();
  const [callbackInfo, setCallbackInfo] = useState<CallbackInfo | null>(null);
  const [tokenSet, setTokenSet] = useState<TokenResponse | null>(null);
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [logs, setLogs] = useState<string[]>([]);

  const authorizeUrl = useMemo(() => `${trimTrailingSlash(baseUrl)}/connect/authorize`, [baseUrl]);
  const tokenUrl = useMemo(() => `${trimTrailingSlash(baseUrl)}/connect/token`, [baseUrl]);
  const userInfoUrl = useMemo(() => `${trimTrailingSlash(baseUrl)}/connect/userinfo`, [baseUrl]);
  const scopes = useMemo(
    () => scopeText.split(/[\s,]+/).map((scope) => scope.trim()).filter(Boolean),
    [scopeText]
  );

  const storedVerifier = isBrowser ? sessionStorage.getItem('pkce_verifier') : null;
  const storedState = isBrowser ? sessionStorage.getItem('pkce_state') : null;

  const canExchange =
    Boolean(callbackInfo?.code && storedVerifier) &&
    (!callbackInfo?.state || callbackInfo.state === storedState);
  const canRefresh = Boolean(tokenSet?.refresh_token);
  const canFetchUserInfo = Boolean(tokenSet?.access_token);

  const handlePkceLogin = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    try {
      setIsRedirecting(true);

      const stateValue = generateState();
      const { verifier, challenge } = await generatePkcePair();

      if (isBrowser) {
        sessionStorage.setItem('pkce_verifier', verifier);
        sessionStorage.setItem('pkce_state', stateValue);
      }

      const url = new URL(authorizeUrl);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('client_id', clientId);
      url.searchParams.set('redirect_uri', redirectUri);
      url.searchParams.set('scope', scopes.join(' '));
      url.searchParams.set('code_challenge', challenge);
      url.searchParams.set('code_challenge_method', 'S256');
      url.searchParams.set('state', stateValue);

      setLastAuthorizeUrl(url.toString());
      log(`🔐 Перенаправление на ${url.toString()}`);
      window.location.href = url.toString();
    } catch (error) {
      handleError(error);
      setIsRedirecting(false);
    }
  };

  const handleTokenExchange = async () => {
    if (!callbackInfo?.code || !storedVerifier) {
      log('⚠️ Нет authorization code или PKCE verifier.');
      return;
    }

    if (callbackInfo.state && callbackInfo.state !== storedState) {
      log('⚠️ Значение state не совпадает с сохранённым.');
      return;
    }

    try {
      setIsExchanging(true);
      const response = await exchangeAuthorizationCode(baseUrl, {
        code: callbackInfo.code,
        codeVerifier: storedVerifier,
        clientId,
        redirectUri,
      });

      setTokenSet(response);
      log('✅ Успешный обмен authorization code на токены.');

      if (isBrowser) {
        sessionStorage.removeItem('pkce_verifier');
        sessionStorage.removeItem('pkce_state');
      }
    } catch (error) {
      handleError(error);
    } finally {
      setIsExchanging(false);
    }
  };

  const handleRefreshTokens = async () => {
    if (!tokenSet?.refresh_token) {
      log('⚠️ Нет refresh токена для обмена.');
      return;
    }

    try {
      setIsRefreshing(true);
      const response = await refreshAccessToken(baseUrl, {
        refreshToken: tokenSet.refresh_token,
        clientId,
      });

      setTokenSet(response);
      log('🔄 Refresh токен обновлён.');
    } catch (error) {
      handleError(error);
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleUserInfo = async () => {
    if (!tokenSet?.access_token) {
      log('⚠️ Нет access токена.');
      return;
    }

    try {
      setIsLoadingUserInfo(true);
      const info = await fetchUserInfo(baseUrl, tokenSet.access_token);
      setUserInfo(info);
      log('ℹ️ Получены данные userinfo.');
    } catch (error) {
      handleError(error);
    } finally {
      setIsLoadingUserInfo(false);
    }
  };

  useEffect(() => {
    if (!isBrowser) {
      return;
    }

    if (window.location.pathname !== '/callback') {
      return;
    }

    const parameters = new URLSearchParams(window.location.search);
    if (parameters.size === 0) {
      return;
    }

    const entries: Record<string, string> = {};
    parameters.forEach((value, key) => {
      entries[key] = value;
    });

    const info: CallbackInfo = {
      parameters: entries,
      code: parameters.get('code') ?? undefined,
      state: parameters.get('state') ?? undefined,
      error: parameters.get('error') ?? undefined,
      error_description: parameters.get('error_description') ?? undefined,
    };

    setCallbackInfo(info);
    if (info.error) {
      log(`❌ Авторизация завершилась ошибкой: ${info.error}`);
    } else if (info.code) {
      log('📥 Получен authorization code, можно обменять его на токен.');
    }
  }, [isBrowser]);

  const handleError = (error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    log(`❌ ${message}`);
  };

  const log = (message: string) => {
    setLogs((prev) => [`${new Date().toLocaleTimeString()} ${message}`, ...prev].slice(0, 50));
  };

  return (
    <div className="app-shell">
      <header className="panel">
        <h1>Auth Playground (PKCE + OIDC)</h1>
        <p>Настройте SPA клиент, выполните PKCE вход и протестируйте ответы /connect/token и /connect/userinfo.</p>
      </header>

      <section className="panel">
        <h2>Параметры клиента</h2>
        <form className="grid two" onSubmit={handlePkceLogin}>
          <label>
            API base URL
            <input value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} required />
          </label>
          <label>
            Client ID
            <input value={clientId} onChange={(e) => setClientId(e.target.value)} required />
          </label>
          <label>
            Redirect URI
            <input value={redirectUri} onChange={(e) => setRedirectUri(e.target.value)} required />
          </label>
          <label>
            Scopes (space separated)
            <input value={scopeText} onChange={(e) => setScopeText(e.target.value)} required />
          </label>
          <div className="url-info">
            <strong>Authorize:</strong> {authorizeUrl}
          </div>
          <div className="url-info">
            <strong>Token:</strong> {tokenUrl}
          </div>
          <button type="submit" disabled={isRedirecting}>
            {isRedirecting ? 'Redirecting…' : 'Start PKCE login'}
          </button>
        </form>
        {lastAuthorizeUrl && (
          <p className="muted">Последний authorize URL: <code>{lastAuthorizeUrl}</code></p>
        )}
      </section>

      <section className="panel">
        <h2>Callback данные</h2>
        {callbackInfo ? (
          <div className="grid">
            <pre>{JSON.stringify(callbackInfo.parameters, null, 2)}</pre>
            <div className="actions">
              <button type="button" onClick={handleTokenExchange} disabled={!canExchange || isExchanging}>
                {isExchanging ? 'Обмен…' : 'Обменять на токен'}
              </button>
            </div>
          </div>
        ) : (
          <p>Ожидаем возврат на redirect URI…</p>
        )}
      </section>

      {tokenSet && (
        <section className="panel">
          <h2>Token response</h2>
          <pre>{JSON.stringify(tokenSet, null, 2)}</pre>
          <div className="actions">
            <button type="button" onClick={handleRefreshTokens} disabled={!canRefresh || isRefreshing}>
              {isRefreshing ? 'Обновление…' : 'Refresh токен'}
            </button>
            <button type="button" onClick={handleUserInfo} disabled={!canFetchUserInfo || isLoadingUserInfo}>
              {isLoadingUserInfo ? 'Запрос…' : 'Получить userinfo'}
            </button>
          </div>
        </section>
      )}

      {userInfo && (
        <section className="panel">
          <h2>Userinfo</h2>
          <pre>{JSON.stringify(userInfo, null, 2)}</pre>
        </section>
      )}

      <section className="panel">
        <h2>Лог</h2>
        <div className="log-panel">
          {logs.length === 0 ? <p>Пока пусто.</p> : logs.map((entry) => <div key={entry}>{entry}</div>)}
        </div>
      </section>
    </div>
  );
}

function trimTrailingSlash(value: string) {
  return value.replace(/\/+$/, '') || value;
}
