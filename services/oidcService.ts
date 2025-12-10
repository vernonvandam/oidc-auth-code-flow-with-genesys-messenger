import { DiscoveryMetadata, OidcConfig, TokenResponse } from '../types';

export const fetchDiscoveryMetadata = async (url: string): Promise<DiscoveryMetadata> => {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch discovery document: ${response.statusText}`);
  }
  return response.json();
};

export const exchangeCodeForToken = async (
  tokenEndpoint: string,
  code: string,
  config: OidcConfig,
  codeVerifier: string
): Promise<TokenResponse> => {
  const body = new URLSearchParams();
  body.append('grant_type', 'authorization_code');
  body.append('code', code);
  body.append('redirect_uri', config.redirectUri);
  body.append('code_verifier', codeVerifier);

  // Include scope in the token request (required by some B2C policies)
  if (config.scope) {
    body.append('scope', config.scope);
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  // Handle Client Authentication
  if (config.clientSecret) {
    if (config.useBasicAuth) {
      // Option 1: Client Secret Basic (Header)
      const credentials = btoa(`${config.clientId}:${config.clientSecret}`);
      headers['Authorization'] = `Basic ${credentials}`;
    } else {
      // Option 2: Client Secret Post (Body) - Default
      body.append('client_id', config.clientId);
      body.append('client_secret', config.clientSecret);
    }
  } else {
    // Public Client (PKCE only)
    body.append('client_id', config.clientId);
  }

  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: headers,
    body: body.toString(),
  });

  if (!response.ok) {
    const errorText = await response.text();
    // Try to parse JSON error for better readability
    try {
        const jsonError = JSON.parse(errorText);
        throw new Error(JSON.stringify(jsonError, null, 2));
    } catch {
        throw new Error(`Token exchange failed: ${errorText}`);
    }
  }

  return response.json();
};

export const parseJwt = (token: string) => {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      window
        .atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    return JSON.parse(jsonPayload);
  } catch (e) {
    return { error: 'Invalid JWT' };
  }
};