import "dotenv/config";
import { GoogleGenAI } from "@google/genai";

// ─── Config ───────────────────────────────────────────────────────────────────

const GEMINI_API_KEY = process.env.GEMINI_API_KEY || "";

// Lazy-initialise the client — only created when a key is present
let _ai = null;
function getClient() {
  if (!_ai) {
    _ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
  }
  return _ai;
}

// ─── Hardcoded fallbacks ──────────────────────────────────────────────────────
// Structured plain-English fallbacks used when no API key is set or API fails.
// Format mirrors what Gemini returns so the CLI renders them consistently.

const FALLBACK_EXPLANATIONS = {
  // ── SAFE ──────────────────────────────────────────────────────────────────
  MIT: [
    "📖 What it means: Do almost anything — use, copy, modify, sell. Just keep the copyright notice.",
    "✅ Can I use it?  Yes — commercial, open-source, proprietary. No restrictions.",
    "📋 Requirements: Include the MIT license text and copyright notice in your distribution.",
    "💡 Do this:      Keep the LICENSE file in your package. Ship it, forget it.",
  ].join("\n"),

  ISC: [
    "📖 What it means: Identical to MIT in practice. Use freely with only attribution required.",
    "✅ Can I use it?  Yes — commercial and proprietary use is fine.",
    "📋 Requirements: Preserve the copyright and permission notice.",
    "💡 Do this:      No extra steps needed. Just keep the license file bundled.",
  ].join("\n"),

  "Apache-2.0": [
    "📖 What it means: Permissive, with an added patent grant. Safe for commercial products.",
    "✅ Can I use it?  Yes — including closed-source and SaaS.",
    "📋 Requirements: Attribution required; note any changes in a NOTICE file if present.",
    "💡 Do this:      Include the NOTICE file in your release. You are protected against patent claims.",
  ].join("\n"),

  "BSD-2-Clause": [
    "📖 What it means: Very permissive. Only two conditions: keep the copyright and don't remove license.",
    "✅ Can I use it?  Yes — safe for any commercial or proprietary product.",
    "📋 Requirements: Retain the copyright notice in source and binary distributions.",
    "💡 Do this:      Bundle the license file. Nothing else needed.",
  ].join("\n"),

  "BSD-3-Clause": [
    "📖 What it means: Like BSD-2 but you cannot use the project's name for endorsement.",
    "✅ Can I use it?  Yes — safe commercially.",
    "📋 Requirements: Keep copyright notice; do not use the author's name to promote your product.",
    "💡 Do this:      Include the license file. Don't imply the original authors endorse your app.",
  ].join("\n"),

  "CC0-1.0": [
    "📖 What it means: The author waived all rights. This is as close to public domain as possible.",
    "✅ Can I use it?  Yes — no conditions whatsoever.",
    "📋 Requirements: None. Zero obligations.",
    "💡 Do this:      Use freely. Attribution is appreciated but not required.",
  ].join("\n"),

  Unlicense: [
    "📖 What it means: Fully public domain. The author has explicitly surrendered all copyright.",
    "✅ Can I use it?  Yes — no strings attached, anywhere.",
    "📋 Requirements: None.",
    "💡 Do this:      Use it. No attribution, no notice, no restrictions of any kind.",
  ].join("\n"),

  WTFPL: [
    '📖 What it means: "Do What The F*** You Want To Public License" — completely unrestricted.',
    "✅ Can I use it?  Yes — no conditions at all.",
    "📋 Requirements: None.",
    "💡 Do this:      Use freely. Some organizations prefer MIT/Apache for legal clarity — consider a swap.",
  ].join("\n"),

  "0BSD": [
    "📖 What it means: Zero-clause BSD. No attribution required. Essentially public domain.",
    "✅ Can I use it?  Yes — even freer than MIT.",
    "📋 Requirements: None.",
    "💡 Do this:      Use without any restrictions.",
  ].join("\n"),

  // ── WARNING ────────────────────────────────────────────────────────────────
  "LGPL-2.0": [
    "📖 What it means: Weak copyleft. You can link to this library without opening your own code.",
    "✅ Can I use it?  Yes for linking, but modifications to the library itself must stay open.",
    "📋 Requirements: Publish changes to the library; allow users to re-link with a modified version.",
    "💡 Do this:      Use it as-is. If you modify the library, those changes must be open-source.",
  ].join("\n"),

  "LGPL-2.1": [
    "📖 What it means: Weak copyleft. Linking in proprietary apps is OK; internal changes must stay open.",
    "✅ Can I use it?  Yes — safe if you use the library without modifying it.",
    "📋 Requirements: Any modifications to this library must be released under LGPL.",
    "💡 Do this:      Do not patch the library source. Use it as a dependency only.",
  ].join("\n"),

  "LGPL-3.0": [
    "📖 What it means: Weak copyleft. Stronger than GPL for end-users but still allows proprietary linking.",
    "✅ Can I use it?  Yes — as a dependency without triggering copyleft.",
    "📋 Requirements: Library modifications must be open-source; users must be able to re-link.",
    "💡 Do this:      Keep the library unmodified. Verify your build does not statically link it.",
  ].join("\n"),

  "MPL-2.0": [
    "📖 What it means: File-level copyleft. Only the files from this package — if modified — must stay open.",
    "✅ Can I use it?  Yes — your own files stay private as long as you keep MPL files separate.",
    "📋 Requirements: Modified MPL-licensed files must be disclosed; your other code is untouched.",
    "💡 Do this:      Keep MPL source files separate. Document any modifications you make to them.",
  ].join("\n"),

  "EPL-2.0": [
    "📖 What it means: Weak copyleft (Eclipse). Modified code in the project must stay open.",
    "✅ Can I use it?  Yes — compatible with some proprietary use when used as a plugin.",
    "📋 Requirements: Distribute any modified EPL files under EPL; binaries need source availability.",
    "💡 Do this:      Avoid modifying the EPL-licensed code. Use it as a black-box dependency.",
  ].join("\n"),

  "EPL-1.0": [
    "📖 What it means: Eclipse Public License v1 — weak copyleft, stricter than v2.",
    "✅ Can I use it?  Cautiously — commercial use is possible but review the terms.",
    "📋 Requirements: Modifications must be released under EPL-1.0.",
    "💡 Do this:      Check if EPL-2.0 is available (it's more compatible). Consult legal if unsure.",
  ].join("\n"),

  "CDDL-1.0": [
    "📖 What it means: Common Development and Distribution License — file-level weak copyleft.",
    "✅ Can I use it?  Cautiously — not compatible with GPL, but usable with some proprietary products.",
    "📋 Requirements: Modified CDDL files must be published under CDDL.",
    "💡 Do this:      Isolate CDDL code from your own. Get legal review for production use.",
  ].join("\n"),

  "CC-BY-SA": [
    "📖 What it means: Creative Commons Share-Alike. Designed for media, not software.",
    "✅ Can I use it?  Risky for code — derivatives must use the same license.",
    "📋 Requirements: Attribution + share-alike: your project must also be CC-BY-SA.",
    "💡 Do this:      Avoid using CC-BY-SA licensed code in software. Look for an alternative package.",
  ].join("\n"),

  Unknown: [
    "📖 What it means: No recognizable license information was found for this package.",
    "✅ Can I use it?  Unknown — no license means copyright is retained by default.",
    "📋 Requirements: Without a license, you technically have no right to use it.",
    "💡 Do this:      Contact the author or find a licensed alternative. Do not ship this in production.",
  ].join("\n"),

  // ── HIGH_RISK ──────────────────────────────────────────────────────────────
  "GPL-1.0": [
    "📖 What it means: Strong copyleft. Any software using this must also be GPL.",
    "✅ Can I use it?  Not in proprietary or closed-source software.",
    "📋 Requirements: Your entire project must be released under GPL-1.0 if distributed.",
    "💡 Do this:      Find a permissively licensed alternative. GPL-1.0 is incompatible with commercial code.",
  ].join("\n"),

  "GPL-2.0": [
    "📖 What it means: Strong copyleft. If you distribute software using this, all code must be GPL-2.0.",
    "✅ Can I use it?  No — not in commercial or proprietary products without legal risk.",
    "📋 Requirements: Full source code of your application must be released under GPL-2.0.",
    "💡 Do this:      Replace this dependency immediately. GPL-2.0 is not compatible with closed-source.",
  ].join("\n"),

  "GPL-3.0": [
    "📖 What it means: Strong copyleft. All derivative works must be open-source under GPL-3.0.",
    "✅ Can I use it?  No — proprietary, SaaS, and commercial products are affected.",
    "📋 Requirements: Release your complete project source under GPL-3.0.",
    '💡 Do this:      Find a MIT/Apache alternative now. GPL-3.0 will "infect" your codebase.',
  ].join("\n"),

  "AGPL-1.0": [
    "📖 What it means: Affero GPL — the strongest copyleft. Even network use triggers the license.",
    "✅ Can I use it?  No — SaaS and any network-accessible service must open all source code.",
    "📋 Requirements: Anyone who accesses your app over a network is entitled to your full source.",
    "💡 Do this:      Remove this dependency immediately. AGPL is incompatible with commercial products.",
  ].join("\n"),

  "AGPL-3.0": [
    "📖 What it means: Strongest copyleft. Using this in a SaaS app means your entire codebase must be open.",
    "✅ Can I use it?  No — if you run it as a service, you must release all source code freely.",
    "📋 Requirements: Full source disclosure required, even for internal/network-only deployments.",
    "💡 Do this:      Replace urgently. AGPL is a show-stopper for any commercial SaaS or proprietary product.",
  ].join("\n"),

  // ── Custom / URL ───────────────────────────────────────────────────────────
  Custom: [
    "📖 What it means: A proprietary or non-standard license was found.",
    "✅ Can I use it?  Unknown — terms vary widely.",
    "📋 Requirements: Read the full license text carefully.",
    "💡 Do this:      Review the license before using in any project. Get legal sign-off for production.",
  ].join("\n"),

  http: [
    "📖 What it means: License terms are hosted at a URL — likely proprietary or non-standard.",
    "✅ Can I use it?  Unknown until you read it.",
    "📋 Requirements: Review the linked license for restrictions.",
    "💡 Do this:      Visit the URL, read the terms, and get legal review before shipping.",
  ].join("\n"),
};

// ─── Gemini SDK call ──────────────────────────────────────────────────────────

/**
 * Calls Gemini 2.0 Flash to generate a plain-English developer-friendly explanation.
 * @param {string} license   - License identifier (SPDX or free-form).
 * @param {string} riskLevel - Pre-classified risk: 'SAFE' | 'WARNING' | 'HIGH_RISK'
 * @returns {Promise<string>} Structured AI explanation.
 */
async function fetchFromGemini(license, riskLevel = "WARNING") {
  const isCustom = /^Custom:/i.test(license) || /^https?:/i.test(license);
  const subject = isCustom
    ? `a custom/proprietary license (reference: ${license.replace(/^Custom:\s*/i, "")})`
    : `the "${license}" software license`;

  const riskEmoji =
    riskLevel === "HIGH_RISK" ? "🔴" : riskLevel === "WARNING" ? "🟡" : "🟢";
  const riskWord =
    riskLevel === "HIGH_RISK"
      ? "HIGH RISK"
      : riskLevel === "WARNING"
        ? "WARNING"
        : "SAFE";

  const prompt = `You are a software license compliance expert writing for developers.

Analyze ${subject} (risk level: ${riskEmoji} ${riskWord}) and explain it in plain English so a developer instantly understands what they can and cannot do.

Reply in EXACTLY this format — no extra text, no markdown headers, no bullet symbols other than shown:

📖 What it means: [1 plain sentence — what this license allows/restricts overall]
✅ Can I use it?  [Safe / Not in proprietary software / Only with conditions — then 1 short reason]
📋 Requirements: [The single most important obligation — what the developer MUST do]
💡 Do this:      [1 direct, actionable recommendation for the developer]

Rules:
- Each line must fit in 90 characters
- Use simple words. No legal jargon.
- Be honest about risks — do not downplay HIGH_RISK licenses
- Do not repeat the license name unnecessarily
- Never add extra lines or sections`;

  const ai = getClient();
  const response = await ai.models.generateContent({
    model: "gemini-2.0-flash",
    contents: prompt,
    config: { maxOutputTokens: 200, temperature: 0.15 },
  });

  const text = response.text?.trim();
  if (!text) throw new Error("Empty Gemini response");
  return text;
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Returns a rich, developer-friendly explanation of a software license.
 *
 * Behavior:
 *  - If GEMINI_API_KEY is set → calls Gemini 2.0 Flash via official SDK.
 *  - If not set              → returns a structured hardcoded fallback.
 *  - If the API call fails   → silently falls back to hardcoded value.
 *
 * @param {string} license   - License identifier (e.g. "MIT", "GPL-3.0").
 * @param {string} riskLevel - Pre-classified risk level for richer prompting.
 * @returns {Promise<string>} Explanation string (multi-line structured format).
 */
export async function getAIExplanation(license, riskLevel = "WARNING") {
  // ── Try live Gemini API if key is available ────────────────────────────────
  if (GEMINI_API_KEY) {
    try {
      return await fetchFromGemini(license, riskLevel);
    } catch (err) {
      // Fall through to hardcoded — don't crash the CLI over an API failure
      // Uncomment for debugging:  console.error('[aiExplainer] Gemini error:', err.message);
    }
  }

  // ── Structured fallback — match on substring for flexibility ──────────────
  for (const [key, explanation] of Object.entries(FALLBACK_EXPLANATIONS)) {
    if (license.includes(key)) return explanation;
  }

  // ── Ultimate fallback for completely unknown licenses ──────────────────────
  return [
    `📖 What it means: "${license}" is not a recognized standard license.`,
    "✅ Can I use it?  Unknown — non-standard licenses carry unpredictable legal risk.",
    "📋 Requirements: Read the full license text to understand your obligations.",
    "💡 Do this:      Have your legal team review this before using in any product.",
  ].join("\n");
}

/**
 * Builds one actionable remediation suggestion for a risky package.
 * Uses Gemini when configured; falls back to deterministic rule-based guidance.
 *
 * @param {{
 *   name: string,
 *   license: string,
 *   risk: 'SAFE' | 'WARNING' | 'HIGH_RISK',
 *   vulns?: Array<{ severity?: string, fixHint?: string | null }>,
 *   supplySignals?: Array<{ type?: string, severity?: string, title?: string }>
 * }} context
 * @returns {Promise<string>}
 */
export async function getRemediationSuggestion(context) {
  const { name, license, risk, vulns = [], supplySignals = [] } = context;

  if (GEMINI_API_KEY) {
    try {
      const vulnSummary = vulns.length
        ? vulns
            .slice(0, 3)
            .map(
              (v) =>
                `${v.severity || "unknown"}${v.fixHint ? ` (fix: ${v.fixHint})` : ""}`,
            )
            .join("; ")
        : "none";

      const signalSummary = supplySignals.length
        ? supplySignals
            .slice(0, 3)
            .map((s) => `${s.type || "signal"}:${s.severity || "unknown"}`)
            .join("; ")
        : "none";

      const prompt = `You are a software supply-chain risk advisor.

Package: ${name}
License: ${license}
License risk: ${risk}
Vulnerabilities: ${vulnSummary}
Supply-chain signals: ${signalSummary}

Return one short actionable remediation sentence for a developer.
Rules:
- 8 to 18 words
- Start with a verb
- Mention package name once
- Prefer practical next action (replace / upgrade / pin / review)
- No markdown, no bullets, no extra lines`;

      const ai = getClient();
      const response = await ai.models.generateContent({
        model: "gemini-2.0-flash",
        contents: prompt,
        config: { maxOutputTokens: 60, temperature: 0.2 },
      });

      const text = response.text?.trim();
      if (text) return text.replace(/\s+/g, " ");
    } catch {
      // Fall through to deterministic fallback.
    }
  }

  // Rule-based fallback order: supply chain > CVEs > license.
  const hasTyposquat = supplySignals.some((s) => s.type === "TYPOSQUAT");
  if (hasTyposquat) {
    return `Verify "${name}" spelling immediately and replace with the intended trusted package.`;
  }

  const hasIntegrityMismatch = supplySignals.some(
    (s) => s.type === "INTEGRITY_MISMATCH",
  );
  if (hasIntegrityMismatch) {
    return `Reinstall ${name} and regenerate lockfile to resolve integrity mismatch before release.`;
  }

  const topVuln = vulns[0];
  if (topVuln?.fixHint) {
    return `Upgrade ${name} now: ${topVuln.fixHint}.`;
  }

  if (vulns.length > 0) {
    return `Upgrade ${name} to a patched version and rerun security checks before shipping.`;
  }

  if (risk === "HIGH_RISK") {
    return `Replace ${name} with an MIT/Apache alternative to avoid strong copyleft obligations.`;
  }

  if (risk === "WARNING") {
    return `Document ${name} license obligations and confirm compliance before commercial distribution.`;
  }

  return `Pin ${name} to a reviewed version and keep it monitored in continuous scans.`;
}

/**
 * Checks whether a Gemini API key is currently configured.
 * @returns {boolean}
 */
export function hasApiKey() {
  return Boolean(GEMINI_API_KEY);
}
