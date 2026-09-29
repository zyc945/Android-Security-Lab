# USB capture: session reliability

Use [lab-rules.md](lab-rules.md) for setup commands and honor the workspace AGENTS.md. These notes address failures observed in the local lab; verify current tool options before applying version-specific behavior.

## Start and prove the path

1. Record the selected serial, original proxy, relevant reverse mappings, and host listeners before changing state. Record the capture directory and process/session ID explicitly; do not select an arbitrary "latest" directory during cleanup.
2. Start mitmweb on host loopback with a persistent terminal (`tty: true`) or a log file so its startup URL is immediately readable. Confirm the process owns the intended proxy/UI ports before directing the phone to it. Do not replace an occupied port or an existing reverse mapping without identifying its owner.
3. Establish the USB reverse and phone proxy for this session. If setup fails after changing the proxy, restore the original network state before retrying.
4. Use the actual startup UI URL, including its token. Verify both authenticated UI access and a decrypted phone HTTPS response. Launching a browser or receiving a queued UI-open result is not verification.

`python3 <skill-dir>/scripts/capture_status.py --serial SERIAL` checks the default 8080/8081 chain. Use port arguments for a deliberately different setup. It performs no phone changes and does not output flow contents or UI tokens.

## mitmweb authentication

Observed on mitmweb 12.2.3: an empty `web_password` generates a random startup token; it does not disable authentication. A UI `403 Authentication Required` is distinct from failure of the phone's proxy traffic.

Retrieve the startup token from the existing session/log and open the complete link. Do not restart a healthy capture just to change authentication unless needed. Do not treat buffered or absent stdout as proof the process failed.

If the user explicitly asks for no login, inspect the installed version's options/source. Prefer a supported setting if available. The local 12.2.3 session used a removable addon that admitted only loopback clients; this is version-specific, not a default configuration. Retain loopback binding and existing origin/XSRF protections. Validate the UI, flows API, and live updates; do not claim live updates work based solely on HTTP 200.

## Phone cannot reach the network

Inspect the chain before changing certificates or restarting services:

| Observation | Next action within an authorized repair |
|---|---|
| Device offline/absent | Recheck USB state. Do not claim proxy cleanup succeeded on an unreachable phone. |
| Proxy targets phone loopback; reverse missing; host proxy healthy | Recreate only the missing session reverse; verify an actual phone HTTPS request. |
| Proxy points to the capture port; host proxy absent | Restore/start the intended service if capture should continue, or restore the original proxy for direct network access. |
| Reverse exists but points elsewhere | Identify its owner; do not overwrite unrelated forwarding. |
| Ordinary HTTPS works but one app fails | Examine app TLS/network behavior; pinning is a hypothesis, not the only cause. Do not repeatedly reinstall CA certificates. |

USB reconnects can remove reverse mappings while Android retains the global proxy. Do not use `adb kill-server`, remove all mappings, or change global security settings as routine recovery. If retaining capture cannot be verified, restore the pre-session proxy where possible and clearly state capture is unavailable.

## Restart or stop

Flush captures by stopping the owned process gracefully. Preserve the old file and use a new output path when restarting; loading old flows and writing a stream can duplicate historical records, so compare flow IDs when counting unique requests.

On stop: restore original proxy (clear only if previously unset), remove the session's reverse if still owned by it, then stop its mitmweb process. Read back network state. Never leave a dead proxy merely because the terminal session ended.
