# Manual WeChat smoke test

1. Start the daemon with a fresh personal data directory.
2. Load the project extension in GitHub Copilot App.
3. Open the **IM Gateway** Canvas and verify daemon health is `ready`.
4. Add your personal WeChat sender ID to the allowlist.
5. Map a non-work test repository to a short workspace alias.
6. Start WeChat login, scan the QR code, and enter a pairing code if requested.
7. Bind the WeChat conversation to the current Copilot session and alias.
8. Send `/status`, then a harmless read-only prompt from WeChat.
9. Confirm only the final assistant response is delivered and local paths are
   redacted.
10. Trigger a write or network permission, verify the rendered scope, approve
    with the one-time nonce, and confirm replaying the nonce is rejected.
11. Restart the daemon and verify login/binding state and audit visibility.

Never perform this test with a Microsoft work repository, work account, or
company data.
