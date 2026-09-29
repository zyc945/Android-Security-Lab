#!/usr/bin/env python3
"""Read-only snapshot of one USB mitmweb capture chain. No repair actions."""
import argparse
import json
import subprocess


def run(args):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=10)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as error:
        return 2, "", str(error)


def classify(proxy, reverse, proxy_listener, ui_listener, port):
    issues = []
    if proxy != f"127.0.0.1:{port}":
        issues.append("phone_proxy_not_targeting_this_capture")
    mappings = [line.split() for line in reverse.splitlines()]
    target = f"tcp:{port}"
    if not any(len(row) >= 3 and row[-2:] == [target, target] for row in mappings):
        issues.append("expected_usb_reverse_missing_or_different")
    for name, listener in (("proxy", proxy_listener), ("ui", ui_listener)):
        lines = listener.splitlines()
        if not any(line.startswith("p") for line in lines):
            issues.append(name + "_listener_missing")
        elif not any(line == "cmitmweb" for line in lines):
            issues.append(name + "_listener_owner_needs_review")
        addresses = [line[1:] for line in lines if line.startswith("n")]
        if any(not address.startswith(("127.0.0.1:", "[::1]:")) for address in addresses):
            issues.append(name + "_listener_not_loopback")
    return issues


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True, help="Currently selected USB device")
    parser.add_argument("--proxy-port", type=int, default=8080)
    parser.add_argument("--web-port", type=int, default=8081)
    args = parser.parse_args()
    if any(not 1 <= port <= 65535 for port in (args.proxy_port, args.web_port)):
        parser.error("ports must be between 1 and 65535")
    adb = ["adb", "-s", args.serial]
    checks = {"device": adb + ["get-state"],
              "proxy": adb + ["shell", "settings", "get", "global", "http_proxy"],
              "reverse": adb + ["reverse", "--list"]}
    for name, port in (("proxy_listener", args.proxy_port), ("ui_listener", args.web_port)):
        checks[name] = ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-Fpcn"]
    results = {name: run(command) for name, command in checks.items()}
    errors = {name: err or f"exit {code}" for name, (code, out, err) in results.items()
              if code and not (name.endswith("listener") and code == 1 and not out and not err)}
    values = {name: out for name, (_, out, _) in results.items()}
    issues = classify(values["proxy"], values["reverse"], values["proxy_listener"],
                      values["ui_listener"], args.proxy_port)
    if values["device"] != "device":
        issues.insert(0, "device_not_online")
    print(json.dumps({"observations": values, "errors": errors, "issues": issues,
                      "https_decryption": "not_tested"}, indent=2))
    return 2 if errors else (1 if issues else 0)


if __name__ == "__main__":
    raise SystemExit(main())
