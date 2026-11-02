/**
 * Security Defanging Utility
 * Converts active web links into safe, non-clickable text strings
 * preventing accidental user click-through or automated chat unfurling.
 */

/**
 * Defangs a URL or domain string.
 * Example: https://paypal.com/login -> hxxps://paypal[.]com/login
 */
export function defangUrl(url: string): string {
  if (!url) return "";

  return url
    .replace(/^https:\/\//i, "hxxps://")
    .replace(/^http:\/\//i, "hxxp://")
    .replace(/^ftp:\/\//i, "fxp://")
    .replace(/\./g, "[.]")
    .replace(/@/g, "[@]");
}

/**
 * Restores a defanged URL back to standard format for analysis.
 */
export function refangUrl(defanged: string): string {
  if (!defanged) return "";

  return defanged
    .replace(/^hxxps:\/\//i, "https://")
    .replace(/^hxxp:\/\//i, "http://")
    .replace(/^fxp:\/\//i, "ftp://")
    .replace(/\[\.\]/g, ".")
    .replace(/\[@\]/g, "@");
}

/**
 * Sanitizes any raw user string to prevent HTML/XSS injection.
 */
export function escapeHtml(unsafe: string): string {
  if (!unsafe) return "";
  return unsafe
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
