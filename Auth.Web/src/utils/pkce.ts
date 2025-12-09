const encoder = new TextEncoder();

export async function generatePkcePair() {
  const verifier = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));
  const challengeData = await crypto.subtle.digest('SHA-256', encoder.encode(verifier));
  const challenge = base64UrlEncode(new Uint8Array(challengeData));
  return { verifier, challenge };
}

export function generateState() {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(16)));
}

function base64UrlEncode(bytes: Uint8Array) {
  const binary = String.fromCharCode(...bytes);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
