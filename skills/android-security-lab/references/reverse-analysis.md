# APK and runtime investigation

## Find the implementation layer

Pull the installed base APK and splits with the wrapper; inspect the returned filenames (this wrapper may prefix them with numbers). Record package version and SHA-256. Inspect assets/native libraries before assuming Java contains the target algorithm:

- Java/Kotlin: JADX and targeted searches/cross-references.
- React Native: inspect `assets/index.android.bundle`; `file` can identify Hermes bytecode and its version. Use a compatible disassembler; plain strings locate candidates but do not prove call semantics.
- Flutter/native/JNI: inspect the relevant libraries and symbols before selecting native analysis tools.

Use static analysis to narrow hooks. For a specific request signature, do not expand into an unrelated full-app security audit. Module IDs, offsets, class names, and embedded configuration values belong to that APK version, not the reusable workflow.

## Frida and Hermes

Check the current target PID and host/server versions. Prefer the lab's matched environment and USB/loopback path. Use narrow observation hooks that preserve arguments and return values. Verify hook readiness before asking the user to reproduce the action. A reloaded script may run setup again: make installation idempotent and retain the original function exactly once, with an explicit restore operation.

Java bridge details observed in the lab:

- Interface objects may need `Java.cast` to the concrete class before invoking implementation-only methods.
- React Native map `.toString()` may only produce `[object Object]`; inspect the relevant getter or map conversion instead of claiming the request body was captured.
- `globalThis` worked in the tested Hermes runtime where `global` did not. Check runtime availability rather than assuming all RN builds expose identical globals.

For evaluating JavaScript through React Native, inspect the app's architecture and installed bridge implementation first. In the tested legacy bridge, `CatalystInstanceImpl.loadScriptFromFile(path, path, false)` queued work onto the JS thread. Do not blindly use synchronous `true` from a Frida callback thread. A process exit occurred during the earlier attempt, but its cause was not conclusively established. This method is not a universal entry point for bridgeless/new-architecture apps.

If a temporary script file is necessary, announce its exact path, impact, and cleanup first. Async submission returning does not prove script completion: wait for a completion marker before deletion, with failure cleanup and readback. A fixed delay alone is not a reliable completion signal. Do not leave temporary code or hooks active when the analysis is finished.

If the process exits, retain relevant logs, check the new PID, and report the interruption. Avoid repeated identical injections. A narrowly scoped, no-network controlled call can validate a function without asking the user to keep repeating actions; label it as controlled validation.

## Prove a signature or parser

Establish exact input serialization (field order, spaces, numeric/string types), key encoding (UTF-8 versus decoded hex), digest/output encoding, and time units. Verify against multiple captured samples where available; repeated calls with the same input are not independent samples.

Separate evidence:

1. Static implementation and configuration source.
2. Runtime observed inputs/outputs or a clearly labeled controlled call.
3. Independent offline reproduction matching captured bytes.
4. An authorized real request, checking both HTTP status and business success.

Do not infer server expiry enforcement or replay rules from a client-side timestamp alone. Do not send new requests merely to document already sufficient offline evidence.

For runnable Python deliverables, verify using the interpreter the user actually invokes. In this lab, `/usr/bin/env python3` used a macOS Python with no default CA bundle while `.venv/bin/python` had a working trust store. Inspect `ssl.get_default_verify_paths()`; use an appropriate trusted CA bundle and retain TLS verification. Do not disable verification as a workaround. A Kotlin translation remains unverified until compiled/tested as appropriate.
