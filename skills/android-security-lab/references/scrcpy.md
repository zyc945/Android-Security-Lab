# USB screen mirroring and control



Use scrcpy when the user wants to operate the lab phone from the computer, paste text or links into it, or manually reproduce app actions while capturing traffic. It is optional for read-only diagnostics and API analysis; do not launch a GUI when the existing CLI is sufficient.

- Check `command -v scrcpy` and `./bin/android-lab devices`; select the currently connected USB device rather than reusing a recorded serial. If scrcpy is missing on macOS, explain the host installation and use `brew install scrcpy` when within the authorized task.
- Before launch, explain that scrcpy temporarily pushes and runs its server on the phone; closing the window stops it and normally removes the server. It does not require installing a persistent Android app.
- Launch `scrcpy -s "$ANDROID_SERIAL" --window-title 'Android USB' --max-size 1600` after setting `ANDROID_SERIAL` to the selected device. Use a persistent terminal session with `tty: true` when available so startup logs are visible. Verify the connected device and renderer/texture startup; do not claim keyboard or mouse input was tested unless actually exercised.
- Keep the default clipboard synchronization enabled for convenient two-way text transfer: Android clipboard changes automatically sync to the computer, while the computer clipboard syncs to Android when pasting. If the user wants to disable automatic synchronization for a session, offer `--no-clipboard-autosync`; do not add it by default.
- For text and links on macOS: copy with Command+C, focus a phone input field in the scrcpy window, then press left Command+V. This copies the computer clipboard to Android and injects paste. If automatic paste fails, long-press the input field and choose Paste. Check the installed `scrcpy --help` for current shortcuts; default MOD is left Alt or left Super (Command on macOS). Do not promise image/file clipboard transfer or use simulated key events as a reliable Unicode fallback.
- Keep a requested interactive window running until the user closes it or asks to stop. Close only the scrcpy session to end mirroring; preserve an ongoing mitmproxy capture, its proxy settings, and its ADB mappings. Avoid `adb kill-server` or removing unrelated forwards during scrcpy cleanup.

