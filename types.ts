export interface OidcConfig {
  authority: string;
  clientId: string;
  redirectUri: string;
  scope: string;
}

export interface GenesysConfig {
  deploymentId: string;
  region: string;
}

export interface DiscoveryMetadata {
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  issuer: string;
  end_session_endpoint?: string;
}

export interface TokenResponse {
  access_token?: string;
  id_token: string;
  refresh_token?: string;
  expires_in?: number;
  token_type?: string;
  scope?: string;
}

export interface AuthState {
  codeVerifier: string;
  state: string;
}
