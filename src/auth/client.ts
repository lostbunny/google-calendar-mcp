import { OAuth2Client } from 'google-auth-library';
import * as fs from 'fs/promises';
import { spawn } from 'child_process';
import { getKeysFilePath, generateCredentialsErrorMessage, OAuthCredentials } from './utils.js';
import { CRED_SOURCE, OP_PATH, OP_VAULT, OP_OAUTH_ITEM } from './credentialConfig.js';

// --- 1Password helpers (used when CRED_SOURCE === 'manager') ---

/** Wraps `op read <ref>` — returns trimmed value or null on failure */
const opRead = (ref: string): Promise<string | null> => new Promise((resolve) => {
  const proc = spawn(OP_PATH, ['read', ref]);
  let out = '';
  proc.stdout.on('data', (d: Buffer) => { out += d; });
  proc.on('close', (code) => resolve(code === 0 ? out.trim() || null : null));
  proc.on('error', () => resolve(null));
});

/** Reads client_id and client_secret from 1Password */
const get1PasswordCredentials = async (): Promise<OAuthCredentials | null> => {
  const clientId     = await opRead(`op://${OP_VAULT}/${OP_OAUTH_ITEM}/username`);
  const clientSecret = await opRead(`op://${OP_VAULT}/${OP_OAUTH_ITEM}/password`);
  if (!clientId || !clientSecret) return null;
  return {
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uris: ['http://localhost:3000/oauth2callback'],
  };
};

// Export opRead so tokenManager can use it for refresh tokens
export { opRead };

async function loadCredentialsFromFile(): Promise<OAuthCredentials> {
  const keysContent = await fs.readFile(getKeysFilePath(), "utf-8");
  const keys = JSON.parse(keysContent);

  if (keys.installed) {
    // Standard OAuth credentials file format
    const { client_id, client_secret, redirect_uris } = keys.installed;
    return { client_id, client_secret, redirect_uris };
  } else if (keys.client_id && keys.client_secret) {
    // Direct format
    return {
      client_id: keys.client_id,
      client_secret: keys.client_secret,
      redirect_uris: keys.redirect_uris || ['http://localhost:3000/oauth2callback']
    };
  } else {
    throw new Error('Invalid credentials file format. Expected either "installed" object or direct client_id/client_secret fields.');
  }
}

async function loadCredentialsWithFallback(): Promise<OAuthCredentials> {
  // CHANGED: dispatch on CRED_SOURCE — no fallback in manager mode
  if (CRED_SOURCE === 'manager') {
    const creds = await get1PasswordCredentials();
    if (!creds) {
      throw new Error(
        'Failed to load OAuth credentials from 1Password. ' +
        'Check OP_VAULT and OP_OAUTH_ITEM env vars and ensure op is unlocked.'
      );
    }
    return creds;
  }

  // ORIGINAL: Load credentials from file (CLI param, env var, or default path)
  try {
    return await loadCredentialsFromFile();
  } catch (fileError) {
    // Generate helpful error message
    const errorMessage = generateCredentialsErrorMessage();
    throw new Error(`${errorMessage}\n\nOriginal error: ${fileError instanceof Error ? fileError.message : fileError}`);
  }
}

export async function initializeOAuth2Client(): Promise<OAuth2Client> {
  // Always use real OAuth credentials - no mocking.
  // Unit tests should mock at the handler level, integration tests need real credentials.
  try {
    const credentials = await loadCredentialsWithFallback();
    
    // Use the first redirect URI as the default for the base client
    return new OAuth2Client({
      clientId: credentials.client_id,
      clientSecret: credentials.client_secret,
      redirectUri: credentials.redirect_uris[0],
    });
  } catch (error) {
    throw new Error(`Error loading OAuth keys: ${error instanceof Error ? error.message : error}`);
  }
}

export async function loadCredentials(): Promise<{ client_id: string; client_secret: string }> {
  try {
    const credentials = await loadCredentialsWithFallback();
    
    if (!credentials.client_id || !credentials.client_secret) {
        throw new Error('Client ID or Client Secret missing in credentials.');
    }
    return {
      client_id: credentials.client_id,
      client_secret: credentials.client_secret
    };
  } catch (error) {
    throw new Error(`Error loading credentials: ${error instanceof Error ? error.message : error}`);
  }
}