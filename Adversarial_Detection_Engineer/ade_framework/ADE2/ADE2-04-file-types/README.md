# ADE2-04 · File Types

Parent category: [ADE2 — Omit Alternatives](../overview.md)

Detection logic checks specific file types/extensions and omits in-scope alternatives — `.zip` but not `.7z`/`.tar`/`.gz`; `.exe` but not `.com`/`.scr`/`.pif`; `.ps1` but not `.psm1`/`.psd1`; `.docx` but not macro-enabled `.docm`.

**Why it's a bug:** extension-based filtering without magic-byte validation misses equivalent formats.

## Techniques

- [Omitted File Extensions and Formats](omitted-file-extensions.md) — a rule's fixed extension list / magic-byte check misses equivalent formats (worked example: BITS ingress omitting non-PE archives, scripts, macro-enabled docs).
- [Interpreter Wrapping and Extension Masquerade](interpreter-wrapper-and-double-extension.md) — running a script through its interpreter (so `process.name` is `bash`/`python`) or renaming/double-extensioning the file defeats script-name and extension logic (documented instances: `bash linpeas.sh`, `.cer`/`.ashx` omissions, `InvoiceDetails.zip.vbs`).
