/**
 * Generates a random string for state or code_verifier
 */
export const generateRandomString = (length: number): string => {
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  let text = '';
  for (let i = 0; i < length; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
};

/**
 * Generates a Code Challenge from a Code Verifier using SHA-256
 */
export const generateCodeChallenge = async (codeVerifier: string): Promise<string> => {
  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const digest = await window.crypto.subtle.digest('SHA-256', data);
  
  return base64UrlEncode(new Uint8Array(digest));
};

/**
 * Base64 URL encoding (different from standard Base64)
 */
const base64UrlEncode = (array: Uint8Array): string => {
  const str = String.fromCharCode.apply(null, Array.from(array));
  const base64 = btoa(str);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};
