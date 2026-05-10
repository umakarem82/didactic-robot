# Security Risk Review (WhatsApp / Aalto-style account hygiene)

## Scope
This review is based on the provided screenshots and focuses on account takeover, social-engineering, and privacy leakage risks.

## Key Findings
1. **Unknown contacts appearing repeatedly** (`Sami ~Sami`) with similar avatars/names indicate possible spoofing or contact poisoning.
2. **Suspicious contact label** (`_$!<C...`) in the edit screen suggests malformed/obfuscated identity metadata.
3. **Group administration controls visible** (Make group admin / Remove from group) increase impact if admin rights are assigned to unverified numbers.
4. **Invite via link or QR code** can expose the group if links are leaked or not rotated.
5. **Search and media indexing with external/unknown contacts** may increase accidental data sharing.

## Risk Level
**Overall: MODERATE to HIGH** (depends on whether unknown identities are trusted and whether 2-step verification is enabled).

## Immediate Actions
- Remove unknown duplicate contacts and block/report suspicious identities.
- Regenerate group invite links and disable old links after membership cleanup.
- Restrict admin privileges to verified contacts only.
- Enable WhatsApp two-step verification and review linked devices.
- Disable automatic media download from unknown contacts/groups.
- Export and preserve chat evidence before deleting suspicious accounts if incident response is needed.

## Patch/Code Hygiene Guidance
Use the `patch-check` mode in `security_review_app.py` to detect suspicious patterns such as:
- dynamic code execution (`eval`, `exec`)
- hard-coded secrets/tokens/passwords
- private key material embedded in source

Example:

```bash
python3 security_review_app.py patch-check . --json
```

If findings appear, remove the suspicious code, rotate exposed credentials, and re-run the scan.
