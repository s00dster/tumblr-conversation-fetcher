/**
 * tumblr_secure_tfa_prompt.php
 * Enhanced Tumblr CLI login script with:
 *   • Secure 0600 cookie file (auto-deleted)
 *   • Optional Two-Factor Authentication (2FA)
 *   • Interactive prompts for missing email/password/blog
 *   • PHP cURL-extension check
 *   • interactive conversation id prompt
 *   • conversation save option
 *
 * Usage examples:
 *   php tumblr_secure_tfa_prompt.php                     # fully interactive
 *   php tumblr_secure_tfa_prompt.php -u email -p pass -b blog
 *   php tumblr_secure_tfa_prompt.php -b blog -t 123456
 */

  CLI Options:

    -u, --username    Tumblr email (prompted if omitted)
    -p, --password    Password (prompted if omitted)
    -b, --blog        Blog name (without .tumblr.com)
    -t, --tfa         2FA code (prompted if omitted when required)
    -c			      conversation id (prompted if omitted when required)
    --skip-ssl        Disable SSL verification (not recommended)
