import React, { useState, useEffect } from 'react';
import { DiscoveryMetadata, OidcConfig, TokenResponse, GenesysConfig } from './types';
import { fetchDiscoveryMetadata, exchangeCodeForToken, parseJwt } from './services/oidcService';
import { generateRandomString, generateCodeChallenge } from './utils/pkce';
import StepCard from './components/StepCard';

const STORAGE_KEY_VERIFIER = 'oidc_code_verifier';
const STORAGE_KEY_STATE = 'oidc_state';
const STORAGE_KEY_CONFIG = 'oidc_config_v2';
const STORAGE_KEY_GENESYS_CONFIG = 'oidc_genesys_config';
const STORAGE_KEY_AUTH_CODE = 'oidc_auth_code';
const STORAGE_KEY_TOKEN_RESPONSE = 'oidc_token_response';

// Clean defaults
const DEFAULT_CONFIG: OidcConfig = {
  authority: '',
  clientId: '',
  clientSecret: '',
  redirectUri: window.location.origin,
  scope: 'openid profile offline_access',
  useBasicAuth: false
};

const DEFAULT_GENESYS_CONFIG: GenesysConfig = {
  deploymentId: '',
  region: 'mypurecloud.com'
};

declare global {
  interface Window {
    Genesys: any;
  }
}

const REGIONS = [
  { value: 'mypurecloud.com', label: 'Americas (US East)' },
  { value: 'usw2.pure.cloud', label: 'US West (Oregon)' },
  { value: 'mypurecloud.ie', label: 'EMEA (Ireland)' },
  { value: 'mypurecloud.de', label: 'EMEA (Frankfurt)' },
  { value: 'mypurecloud.com.au', label: 'APAC (Sydney)' },
  { value: 'mypurecloud.jp', label: 'APAC (Japan)' },
  { value: 'cac1.pure.cloud', label: 'Canada' },
];

// Mapping domains to specific Genesys environment short-codes
const getGenesysEnv = (domain: string): string => {
    const mappings: {[key: string]: string} = {
        'mypurecloud.com': 'prod',
        'usw2.pure.cloud': 'prod-usw2',
        'mypurecloud.ie': 'prod-euw1',
        'mypurecloud.de': 'prod-euc1',
        'mypurecloud.com.au': 'prod-apse2',
        'mypurecloud.jp': 'prod-apne1',
        'cac1.pure.cloud': 'prod-cac1'
    };
    return mappings[domain] || domain;
};

const App: React.FC = () => {
  // Initialize config from localStorage
  const [config, setConfig] = useState<OidcConfig>(() => {
    const saved = localStorage.getItem(STORAGE_KEY_CONFIG);
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        return { ...DEFAULT_CONFIG, ...parsed, redirectUri: window.location.origin };
      } catch (e) {
        console.error("Failed to parse saved config", e);
      }
    }
    return DEFAULT_CONFIG;
  });

  const [genesysConfig, setGenesysConfig] = useState<GenesysConfig>(() => {
    const saved = localStorage.getItem(STORAGE_KEY_GENESYS_CONFIG);
    if (saved) {
      try { return { ...DEFAULT_GENESYS_CONFIG, ...JSON.parse(saved) }; } 
      catch { return DEFAULT_GENESYS_CONFIG; }
    }
    return DEFAULT_GENESYS_CONFIG;
  });

  const [metadata, setMetadata] = useState<DiscoveryMetadata | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  const [authCode, setAuthCode] = useState<string | null>(() => {
    return localStorage.getItem(STORAGE_KEY_AUTH_CODE);
  });

  const [tokenResponse, setTokenResponse] = useState<TokenResponse | null>(() => {
    const saved = localStorage.getItem(STORAGE_KEY_TOKEN_RESPONSE);
    try { return saved ? JSON.parse(saved) : null; } 
    catch { return null; }
  });

  const [decodedToken, setDecodedToken] = useState<any>(null);
  
  const [discoveryStatus, setDiscoveryStatus] = useState<'pending' | 'active' | 'success' | 'error'>('pending');
  const [authStatus, setAuthStatus] = useState<'pending' | 'active' | 'success' | 'error'>(() => 
    localStorage.getItem(STORAGE_KEY_AUTH_CODE) ? 'success' : 'pending'
  );
  const [tokenStatus, setTokenStatus] = useState<'pending' | 'active' | 'success' | 'error'>(() => 
    localStorage.getItem(STORAGE_KEY_TOKEN_RESPONSE) ? 'success' : 'pending'
  );
  
  const [messengerStatus, setMessengerStatus] = useState<'idle' | 'loading' | 'ready' | 'error'>('idle');
  const [hasRegisteredAuthProvider, setHasRegisteredAuthProvider] = useState(false);

  // Persistence Effects
  useEffect(() => {
    localStorage.setItem(STORAGE_KEY_CONFIG, JSON.stringify(config));
  }, [config]);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY_GENESYS_CONFIG, JSON.stringify(genesysConfig));
  }, [genesysConfig]);

  useEffect(() => {
    if (authCode) {
      localStorage.setItem(STORAGE_KEY_AUTH_CODE, authCode);
    } else {
      localStorage.removeItem(STORAGE_KEY_AUTH_CODE);
    }
  }, [authCode]);

  useEffect(() => {
    if (tokenResponse) {
      localStorage.setItem(STORAGE_KEY_TOKEN_RESPONSE, JSON.stringify(tokenResponse));
    } else {
      localStorage.removeItem(STORAGE_KEY_TOKEN_RESPONSE);
    }
  }, [tokenResponse]);

  // Decode token effect
  useEffect(() => {
    if (tokenResponse) {
      if (tokenResponse.id_token) {
        setDecodedToken(parseJwt(tokenResponse.id_token));
      } else if (tokenResponse.access_token) {
        setDecodedToken(parseJwt(tokenResponse.access_token));
      }
    } else {
      setDecodedToken(null);
    }
  }, [tokenResponse]);

  // Handle URL parameters (Callback phase)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const state = params.get('state');
    const errorParam = params.get('error');
    const errorDesc = params.get('error_description');

    if (code) {
      setAuthCode(code);
      setAuthStatus('success');
      window.history.replaceState({}, document.title, window.location.pathname);
      
      const storedState = sessionStorage.getItem(STORAGE_KEY_STATE);
      if (state && state !== storedState) {
        setError('State mismatch! Possible CSRF attack.');
        setAuthStatus('error');
      }
    } else if (errorParam) {
      setError(`${errorParam}: ${errorDesc}`);
      setAuthStatus('error');
    }
  }, []);

  // Auto-Discovery Effect
  useEffect(() => {
    const fetchMetadata = async () => {
      if (!config.authority) {
        setMetadata(null);
        return;
      }
      if (!config.authority.startsWith('http') || config.authority.length < 10) return;

      setDiscoveryStatus('active');
      setError(null);
      try {
        const data = await fetchDiscoveryMetadata(config.authority);
        setMetadata(data);
        setDiscoveryStatus('success');
      } catch (err: any) {
        setError(err.message);
        setDiscoveryStatus('error');
        setMetadata(null);
      }
    };
    const debounceTimer = setTimeout(fetchMetadata, 800);
    return () => clearTimeout(debounceTimer);
  }, [config.authority]);

  // Step 2: Trigger Login
  const handleLogin = async () => {
    if (!metadata) return;
    if (!config.clientId) {
        setError("Client ID is required.");
        return;
    }

    setAuthStatus('active');
    const codeVerifier = generateRandomString(64);
    const codeChallenge = await generateCodeChallenge(codeVerifier);
    const state = generateRandomString(32);

    sessionStorage.setItem(STORAGE_KEY_VERIFIER, codeVerifier);
    sessionStorage.setItem(STORAGE_KEY_STATE, state);

    try {
      const urlObj = new URL(metadata.authorization_endpoint);
      urlObj.searchParams.append('client_id', config.clientId);
      urlObj.searchParams.append('response_type', 'code');
      urlObj.searchParams.append('redirect_uri', config.redirectUri);
      urlObj.searchParams.append('scope', config.scope);
      urlObj.searchParams.append('response_mode', 'query');
      urlObj.searchParams.append('state', state);
      urlObj.searchParams.append('code_challenge', codeChallenge);
      urlObj.searchParams.append('code_challenge_method', 'S256');

      window.location.href = urlObj.toString();
    } catch (e) {
      setError("Failed to construct authorization URL.");
      setAuthStatus('error');
    }
  };

  // Step 3: Exchange Code for Token
  const handleTokenExchange = async () => {
    if (!metadata || !authCode) return;
    setTokenStatus('active');
    const verifier = sessionStorage.getItem(STORAGE_KEY_VERIFIER);

    if (!verifier) {
      setError('No code verifier found in session storage.');
      setTokenStatus('error');
      return;
    }

    try {
      const response = await exchangeCodeForToken(
        metadata.token_endpoint,
        authCode,
        config,
        verifier
      );
      setTokenResponse(response);
      setTokenStatus('success');
    } catch (err: any) {
      setError(err.message);
      setTokenStatus('error');
    }
  };

  // Initialize Genesys Messenger
  const initializeGenesys = () => {
    const deploymentId = genesysConfig.deploymentId?.trim();
    const regionDomain = genesysConfig.region?.trim();

    if (!deploymentId) {
      setError("Genesys Deployment ID is required.");
      return;
    }

    // Resolve environment short-code (e.g., 'prod-apse2')
    const environment = getGenesysEnv(regionDomain);

    console.log(`[Genesys Debug] Initializing with ID: "${deploymentId}" in region: "${regionDomain}" (Env: ${environment})`);

    setMessengerStatus('loading');
    
    const scriptId = 'genesys-messenger-script';
    
    if (!document.getElementById(scriptId)) {
        // CLEANUP: Ensure we don't have a stale global function from a failed previous load
        if ((window as any).Genesys) {
             delete (window as any).Genesys;
        }

        // Configure the environment and deployment ID here
        const genesysConfigObj = {
            environment: environment,
            deploymentId: deploymentId
        };

        // Stub derived from user provided code, matching exactly
        (function (g: any, e, n, es, ys) {
            g['_genesysJs'] = e;
            g[e] = g[e] || function () {
              (g[e].q = g[e].q || []).push(arguments)
            };
            g[e].t = 1 * (new Date() as any); // Type cast for TS
            g[e].c = es; 
            
            ys = document.createElement('script'); 
            ys.async = true; 
            ys.src = n; 
            ys.charset = 'utf-8';
            ys.id = scriptId;
            ys.onload = () => {
                console.log("[Genesys Debug] Script Loaded");
                setMessengerStatus('ready');
                registerGenesysAuthProvider();
            };
            ys.onerror = () => {
                setMessengerStatus('error');
                setError("Failed to load Genesys Messenger script.");
            }; 
            document.head.appendChild(ys);
        })(window, 'Genesys', `https://apps.${regionDomain}/genesys-bootstrap/genesys.min.js`, genesysConfigObj);

    } else {
        // Already loaded
        console.log("[Genesys Debug] Script already exists in DOM");
        setMessengerStatus('ready');
        // Register AuthProvider after Messenger is ready
        (window as any).Genesys("subscribe", "Messenger.ready", () => {
            if (!hasRegisteredAuthProvider) {
                console.log("[Genesys Debug] Messenger ready, registering AuthProvider");
                registerGenesysAuthProvider();
            }
        });
    }
  };

  const registerGenesysAuthProvider = () => {
    if (hasRegisteredAuthProvider) {
      console.log("[Genesys Debug] AuthProvider already registered, skipping");
      return;
    }
    if (!(window as any).Genesys) return;

    setHasRegisteredAuthProvider(true);

    (window as any).Genesys("registerPlugin", "AuthProvider", (AuthProvider: any) => {
        console.log("[Genesys Debug] AuthProvider registering...");

        AuthProvider.registerCommand("getAuthCode", (e: any) => {
            console.log("[Genesys Debug] getAuthCode called by Messenger", e.data);
            const { forceUpdate } = e.data || {};

            if (forceUpdate) {
                console.log("[Genesys Debug] Force update requested, triggering login");
                handleLogin();
                e.resolve();
                return;
            }

            const verifier = sessionStorage.getItem(STORAGE_KEY_VERIFIER);

            if (authCode && verifier) {
                console.log("[Genesys Debug] Providing auth code to Messenger");
                e.resolve({
                    authCode: authCode,
                    redirectUri: config.redirectUri,
                    codeVerifier: verifier
                });
            } else {
                console.error("[Genesys Debug] Missing auth code or verifier");
                e.reject("No auth code or verifier available. Please authorize first.");
            }
        });

        AuthProvider.registerCommand("reAuthenticate", (e: any) => {
             console.log("[Genesys Debug] reAuthenticate requested");
             // Trigger re-authentication by starting the login flow again
             handleLogin();
             e.resolve();
        });

        // Subscribe to Auth events
        AuthProvider.subscribe('Auth.ready', () => {
            console.log("[Genesys Debug] Auth.ready - Auth plugin is ready");
        });

        AuthProvider.subscribe('Auth.authenticated', () => {
            console.log("[Genesys Debug] Auth.authenticated - User authenticated successfully");
        });

        AuthProvider.subscribe('Auth.error', (error: any) => {
            console.log("[Genesys Debug] Auth.error", error?.data?.message || error);
        });

        AuthProvider.subscribe('Auth.authError', (error: any) => {
            console.log("[Genesys Debug] Auth.authError", error);
        });

        // Tell Messenger that your plugin is ready (mandatory)
        AuthProvider.ready();
    });
  };

  const handleReset = () => {
    if (window.confirm("Are you sure you want to reset all configuration and state? This will reload the page.")) {
      // Clear storage
      localStorage.clear();
      sessionStorage.clear();
      
      // Force reload is required to clear Genesys global state completely
      window.location.reload();
    }
  };

  const isConfigComplete = Boolean(metadata && config.clientId && config.clientSecret);
  const isGenesysReady = Boolean(genesysConfig.deploymentId && authCode);

  return (
    <div className="min-h-screen bg-gray-50 pb-12">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center">
            <div className="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center mr-3">
              <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
            </div>
            <h1 className="text-xl font-bold text-gray-900">OIDC Auth Code Flow Debugger</h1>
          </div>
          <div className="text-xs text-gray-500 font-mono">
            v1.6.3
          </div>
        </div>
      </header>

      {/* Warning Banner */}
      <div className="bg-yellow-50 border-b border-yellow-200 p-4">
        <div className="max-w-5xl mx-auto flex items-start">
          <svg className="w-5 h-5 text-yellow-600 mt-0.5 mr-3 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
          </svg>
          <div>
            <h3 className="text-sm font-medium text-yellow-800">Security Warning: Client Secret in Frontend</h3>
            <p className="mt-1 text-sm text-yellow-700">
              This application includes a <strong>Client Secret</strong> in the client-side code (browser). 
              This is <strong>NOT RECOMMENDED</strong> for production applications. 
            </p>
          </div>
        </div>
      </div>

      <main className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        
        {/* Error Display */}
        {error && (
          <div className="mb-6 bg-red-50 border border-red-200 rounded-lg p-4 flex items-center text-red-700">
            <svg className="w-5 h-5 mr-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
               <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <span className="font-medium whitespace-pre-wrap">{error}</span>
            <button onClick={() => setError(null)} className="ml-auto text-sm underline">Dismiss</button>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* Left Column: Configuration */}
          <div className="lg:col-span-1 space-y-6">
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-lg font-semibold text-gray-900">OIDC Config</h2>
                <button 
                  onClick={handleReset} 
                  className="text-xs text-red-600 hover:text-red-800 font-medium px-2 py-1 rounded hover:bg-red-50 transition-colors"
                  title="Clear all local data and reset fields"
                >
                  Reset
                </button>
              </div>
              
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-gray-500 uppercase tracking-wider mb-1">Discovery Endpoint</label>
                  <input 
                    type="text" 
                    placeholder="https://.../.well-known/openid-configuration"
                    value={config.authority}
                    onChange={(e) => setConfig({...config, authority: e.target.value})}
                    className="w-full text-sm border-gray-300 rounded-md shadow-sm focus:border-blue-500 focus:ring-blue-500 border p-2 bg-gray-50"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-500 uppercase tracking-wider mb-1">Client ID</label>
                  <input 
                    type="text" 
                    value={config.clientId}
                    onChange={(e) => setConfig({...config, clientId: e.target.value})}
                    className="w-full text-sm border-gray-300 rounded-md shadow-sm focus:border-blue-500 focus:ring-blue-500 border p-2"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-500 uppercase tracking-wider mb-1">Client Secret</label>
                  <input 
                    type="password" 
                    value={config.clientSecret}
                    onChange={(e) => setConfig({...config, clientSecret: e.target.value})}
                    className="w-full text-sm border-gray-300 rounded-md shadow-sm focus:border-blue-500 focus:ring-blue-500 border p-2 bg-yellow-50"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-500 uppercase tracking-wider mb-1">Redirect URI</label>
                  <input 
                    type="text" 
                    value={config.redirectUri}
                    readOnly
                    className="w-full text-sm border-gray-300 rounded-md bg-gray-100 text-gray-500 border p-2 cursor-not-allowed"
                  />
                  <p className="text-xs text-gray-400 mt-1">Must match Azure AD B2C config exactly.</p>
                </div>
              </div>
            </div>

            {/* Genesys Config Card */}
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Genesys Config</h2>
              <div className="space-y-4">
                 <div>
                    <label className="block text-xs font-medium text-gray-500 uppercase tracking-wider mb-1">Deployment ID</label>
                    <input 
                      type="text" 
                      value={genesysConfig.deploymentId}
                      onChange={(e) => setGenesysConfig({...genesysConfig, deploymentId: e.target.value})}
                      placeholder="e.g. 1234-5678-..."
                      className="w-full text-sm border-gray-300 rounded-md shadow-sm focus:border-blue-500 focus:ring-blue-500 border p-2"
                    />
                 </div>
                 <div>
                    <label className="block text-xs font-medium text-gray-500 uppercase tracking-wider mb-1">Region</label>
                    <select
                      value={genesysConfig.region}
                      onChange={(e) => setGenesysConfig({...genesysConfig, region: e.target.value})}
                      className="w-full text-sm border-gray-300 rounded-md shadow-sm focus:border-blue-500 focus:ring-blue-500 border p-2 bg-white"
                    >
                      {REGIONS.map(r => (
                        <option key={r.value} value={r.value}>{r.label}</option>
                      ))}
                    </select>
                 </div>
              </div>
            </div>
            
            <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
              <h2 className="text-lg font-semibold text-gray-900 mb-4">Endpoints Discovered</h2>
              {metadata ? (
                <div className="space-y-3 text-xs font-mono break-all mb-4">
                  <div>
                    <span className="text-green-600 font-bold">Auth:</span>
                    <p className="text-gray-600 mt-1">{metadata.authorization_endpoint}</p>
                  </div>
                  <div className="border-t pt-2">
                    <span className="text-blue-600 font-bold">Token:</span>
                    <p className="text-gray-600 mt-1">{metadata.token_endpoint}</p>
                  </div>
                </div>
              ) : (
                 <div className="text-sm text-gray-400 italic mb-4">Waiting for discovery URL...</div>
              )}
            </div>
          </div>

          {/* Right Column: Flow Execution */}
          <div className="lg:col-span-2 space-y-4">
            
            {/* Step 1: Authorization */}
            <StepCard title="1. User Authorization" status={authCode ? 'success' : authStatus === 'active' ? 'active' : 'pending'}>
              <div className="space-y-4">
                <p className="text-sm">
                  Initiate the Authorization Code Flow. This will redirect the user to the Identity Provider to sign in.
                </p>
                {!authCode ? (
                  <button
                    onClick={handleLogin}
                    disabled={!isConfigComplete}
                    className={`inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white 
                      ${!isConfigComplete ? 'bg-gray-300 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'}`}
                  >
                    {!metadata 
                      ? 'Waiting for Discovery...' 
                      : (!config.clientId || !config.clientSecret ? 'Enter Client Details' : 'Authorize User')
                    }
                  </button>
                ) : (
                  <div className="bg-green-50 rounded p-3 border border-green-200">
                     <p className="text-xs font-bold text-green-800 uppercase mb-1">Authorization Code Received</p>
                     <code className="text-xs break-all text-green-700 block">{authCode}</code>
                  </div>
                )}
              </div>
            </StepCard>

             {/* Split View for Token Exchange OR Genesys */}
             {authCode && !tokenResponse && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Option A: Debugger */}
                    <div className="border-2 border-dashed border-gray-300 rounded-lg p-4">
                        <h4 className="font-semibold text-gray-900 mb-2">Option A: Debug Tokens</h4>
                        <p className="text-xs text-gray-500 mb-4">
                            Exchange the code now to view tokens. <span className="text-red-500 font-bold">This will consume the code</span>, making it invalid for Genesys.
                        </p>
                        <button
                            onClick={handleTokenExchange}
                            className="w-full inline-flex justify-center items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700"
                        >
                            Exchange Code for Token
                        </button>
                    </div>

                    {/* Option B: Genesys */}
                    <div className="border-2 border-dashed border-gray-300 rounded-lg p-4">
                        <h4 className="font-semibold text-gray-900 mb-2">Option B: Genesys Messenger</h4>
                        <p className="text-xs text-gray-500 mb-4">
                            Pass the auth code to Genesys Messenger. Ensure Deployment ID is set.
                        </p>
                        <button
                            onClick={initializeGenesys}
                            disabled={!isGenesysReady || messengerStatus === 'loading' || messengerStatus === 'ready'}
                            className={`w-full inline-flex justify-center items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white 
                                ${!isGenesysReady ? 'bg-gray-300 cursor-not-allowed' : 'bg-orange-600 hover:bg-orange-700'}`}
                        >
                            {messengerStatus === 'loading' ? 'Loading...' : messengerStatus === 'ready' ? 'Messenger Loaded' : 'Initialize Genesys'}
                        </button>
                    </div>
                </div>
             )}

            {/* Step 2: Token Exchange (Only show if used) */}
            {(tokenResponse || (!authCode && tokenStatus !== 'pending')) && (
                <StepCard title="2. Token Exchange (Debug View)" status={tokenResponse ? 'success' : tokenStatus === 'active' ? 'active' : 'pending'}>
                <div className="space-y-4">
                    {!tokenResponse ? (
                    <p className="text-sm text-gray-500">Waiting for code exchange...</p>
                    ) : (
                    <div className="space-y-4">
                        <div className="bg-indigo-50 rounded p-3 border border-indigo-200">
                            <p className="text-xs font-bold text-indigo-800 uppercase mb-1">Access Token (Truncated)</p>
                            <code className="text-xs break-all text-indigo-700 block mb-2">
                            {tokenResponse.access_token.substring(0, 50)}...
                            </code>
                            <div className="flex gap-2">
                            <span className="text-xs px-2 py-1 bg-indigo-100 text-indigo-800 rounded">
                                Expires in: {tokenResponse.expires_in}s
                            </span>
                            </div>
                        </div>
                    </div>
                    )}
                </div>
                </StepCard>
            )}

            {/* Step 3: Genesys Status (Only show if initialized) */}
            {messengerStatus !== 'idle' && (
                 <StepCard title="3. Genesys Cloud Messenger" status={messengerStatus === 'ready' ? 'success' : messengerStatus === 'loading' ? 'active' : 'error'}>
                     <div className="space-y-2">
                        {messengerStatus === 'ready' && (
                            <div className="text-sm text-green-700 flex items-center">
                                <svg className="w-5 h-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                </svg>
                                Messenger Loaded & Auth Provider Registered. 
                            </div>
                        )}
                        <p className="text-sm text-gray-600">
                             Open the messenger widget in the bottom right corner. When you interact with it, it will use the OIDC Auth Code to sign in.
                        </p>
                        {tokenResponse && (
                            <div className="bg-yellow-50 p-2 rounded border border-yellow-200 text-xs text-yellow-800">
                                <strong>Warning:</strong> You have already exchanged the code in this app (Option A). Genesys authentication will likely fail because the code is consumed. Please "Reset" and "Authorize" again, then choose Option B.
                            </div>
                        )}
                     </div>
                 </StepCard>
            )}

            {/* User Profile / Token Data */}
            {decodedToken && (
              <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
                <div className="px-6 py-4 border-b border-gray-200 bg-gray-50 flex justify-between items-center">
                  <h3 className="text-lg font-medium text-gray-900">Decoded Token Claims</h3>
                  <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">
                    Verified
                  </span>
                </div>
                <div className="p-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {Object.entries(decodedToken).map(([key, value]) => (
                      <div key={key} className="border-b border-gray-100 pb-2 last:border-0">
                        <dt className="text-xs font-medium text-gray-500 uppercase">{key}</dt>
                        <dd className="mt-1 text-sm text-gray-900 font-mono break-all">
                          {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                        </dd>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Debugging: Raw JSON */}
            {tokenResponse && (
               <div className="mt-8">
                  <details className="group">
                    <summary className="list-none flex items-center cursor-pointer text-sm text-gray-500 hover:text-gray-700">
                      <svg className="w-4 h-4 mr-2 transform group-open:rotate-90 transition-transform" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                      </svg>
                      View Raw Token Response
                    </summary>
                    <div className="mt-4 bg-gray-900 rounded-lg p-4 overflow-x-auto">
                      <pre className="text-xs text-green-400 font-mono">
                        {JSON.stringify(tokenResponse, null, 2)}
                      </pre>
                    </div>
                  </details>
               </div>
            )}

          </div>
        </div>
      </main>
    </div>
  );
};

export default App;
