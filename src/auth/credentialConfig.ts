/**
 * Credential manager configuration
 *
 * Controls how OAuth credentials and refresh tokens are sourced:
 *   CRED_SOURCE="file"    → original behaviour (read gcp-oauth.keys.json + tokens.json)
 *   CRED_SOURCE="manager" → read client_id / client_secret / refresh_tokens from 1Password;
 *                            never write secrets to disk
 */

export const CRED_SOURCE      = process.env.CRED_SOURCE       || 'file';
export const OP_PATH          = process.env.OP_PATH            || 'op';
export const OP_VAULT         = process.env.OP_VAULT           || '';
export const OP_OAUTH_ITEM    = process.env.OP_OAUTH_ITEM      || '';
export const OP_ACCOUNTS_FILE = process.env.OP_ACCOUNTS_FILE   || '';
