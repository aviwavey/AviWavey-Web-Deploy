import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
export const adminCookie = '__Host-avi_admin';
export const challengeCookie = '__Host-avi_admin_challenge';
export const products = ['avi', 'aura', 'mike'];
export const roles = ['owner', 'administrator', 'moderator', 'support', 'analyst'];
const permissions = {
  administrator: ['overview.read', 'identity.read', 'security.read', 'safety.review', 'support.read', 'analytics.read'],
  moderator: ['overview.read', 'safety.review'],
  support: ['overview.read', 'support.read'],
  analyst: ['overview.read', 'analytics.read'],
};
export function permitted(account, product, permission) {
  if (!account || account.status !== 'active' || !products.includes(product) || !roles.includes(account.role)) return false;
  if (account.role === 'owner') return true;
  // Cross-product access is reserved for the owner, including administrators.
  return Array.isArray(account.products) && account.products.length === 1 && account.products[0] === product && permissions[account.role]?.includes(permission) === true;
}
export const token = () => randomBytes(32).toString('base64url');
export const digest = value => createHash('sha256').update(value).digest('hex');
export function matchesEnrollment(value, hash, expiresAt, now = Date.now()) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value) || !/^[a-f0-9]{64}$/.test(hash || '')) return false;
  const expiry = Date.parse(expiresAt || '');
  return Number.isFinite(expiry) && expiry > now && expiry <= now + 86400000 && timingSafeEqual(Buffer.from(digest(value), 'hex'), Buffer.from(hash, 'hex'));
}
export function cookie(name, value, seconds) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${seconds}`;
}
export function readCookie(header, name) {
  const values = (header || '').split(';').map(v => v.trim()).filter(v => v.startsWith(name + '=')).map(v => v.slice(name.length + 1));
  return values.length === 1 && /^[A-Za-z0-9_-]{43}$/.test(values[0]) ? values[0] : null;
}
export function validSession(row, now = Date.now()) {
  return Boolean(row && row.status === 'active' && !row.revoked_at && Date.parse(row.expires_at) > now && Date.parse(row.last_seen) > now - 30 * 60000);
}
export function requireSameOrigin(method, origin, site, expected) {
  return site !== 'cross-site' && (method === 'GET' ? !origin || origin === expected : origin === expected);
}
export function publicAccount(row) { return { id: row.id, email: row.email, role: row.role, products: row.role === 'owner' ? products : row.products }; }
