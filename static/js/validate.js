/**
 * Client-side input validation - OWASP Top Ten Proactive Controls (2024),
 * C3: Validate All Input.
 *
 * IMPORTANT: this is a UX convenience only. It is NOT a security boundary
 * by itself - it can be bypassed by disabling JS, editing the DOM, or
 * calling POST /search directly. The backend (app.py) re-runs the exact
 * same checks and is the actual trust boundary. Mirroring the rules here
 * just gives the user immediate feedback and avoids a round trip for
 * obviously invalid input.
 *
 * Rules mirror the backend:
 *  - length between MIN_LEN and MAX_LEN
 *  - allow-list: letters, digits, spaces, and . , - _ ? !
 *  - deny-list: common SQLi / XSS payload signatures
 */
(function () {
  "use strict";

  const MIN_LEN = 2;
  const MAX_LEN = 50;

  const ALLOWED_PATTERN = /^[A-Za-z0-9 .,_\-?!]+$/;

  const ATTACK_PATTERNS = [
    /--/,
    /;/,
    /\/\*|\*\//,
    /<\s*script/i,
    /<\s*\/\s*script/i,
    /<\s*iframe/i,
    /<\s*img/i,
    /javascript\s*:/i,
    /on\w+\s*=/i,
    /\bunion\b\s+\bselect\b/i,
    /\bselect\b.+\bfrom\b/i,
    /\binsert\b\s+\binto\b/i,
    /\bupdate\b.+\bset\b/i,
    /\bdelete\b\s+\bfrom\b/i,
    /\bdrop\b\s+\btable\b/i,
    /\bexec\b\s*\(/i,
    /\balert\b\s*\(/i,
    /'\s*or\s*'?\d*'?\s*=\s*'?\d*/i,
  ];

  function validateSearchTerm(raw) {
    const term = (raw || "").trim();

    if (term.length === 0) {
      return { ok: false, reason: "Search term is required." };
    }
    if (term.length < MIN_LEN || term.length > MAX_LEN) {
      return {
        ok: false,
        reason: `Search term must be between ${MIN_LEN} and ${MAX_LEN} characters.`,
      };
    }
    if (!ALLOWED_PATTERN.test(term)) {
      return {
        ok: false,
        reason:
          "Only letters, numbers, spaces, and . , - _ ? ! are allowed.",
      };
    }
    for (const pattern of ATTACK_PATTERNS) {
      if (pattern.test(term)) {
        return {
          ok: false,
          reason: "Search term rejected: input looks like an attack payload.",
        };
      }
    }
    return { ok: true, term: term };
  }

  document.addEventListener("DOMContentLoaded", function () {
    const form = document.getElementById("search-form");
    const input = document.getElementById("search_term");
    const errorEl = document.getElementById("client-error");

    if (!form || !input || !errorEl) return;

    form.addEventListener("submit", function (event) {
      const check = validateSearchTerm(input.value);

      if (!check.ok) {
        event.preventDefault();
        errorEl.textContent = check.reason;
        errorEl.hidden = false;
        // Per requirement: clear the input and remain on the home page
        // for a new attempt.
        input.value = "";
        input.focus();
        return;
      }

      errorEl.hidden = true;
      // Let the (now-validated) form submit normally to POST /search,
      // where the backend performs its own authoritative validation.
    });

    // Clear inline error as soon as the user starts typing again.
    input.addEventListener("input", function () {
      if (!errorEl.hidden) {
        errorEl.hidden = true;
      }
    });
  });
})();
