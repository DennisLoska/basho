# Typed containment with separate privileged enforcement

Basho runs unprivileged as the local user, while host network containment (`ufw` / `nftables`) requires root privileges and carries severe self-lockout risk if an LLM emits arbitrary shell commands. We restrict containment to a closed, typed action allowlist evaluated deterministically by Basho's lockdown engine, and isolate privileged network mutations inside an opt-in, root-owned helper script (`scripts/basho-lockdown-helper.sh`) with its own `DeadMansSwitch` checks and independent lease expiry.

**Considered Options:**
- Allow the AI analyst to execute generated shell commands via `sudo`: rejected due to prompt-injection RCE and self-lockout risks.
- Run Basho itself as root: rejected to preserve least privilege for a web dashboard.

**Consequences:**
- Privileged actions (`deny_peer_ip`, `isolate_lan_ingress`) remain cleanly unavailable (or fall back to the `approve` queue with copyable guidance) until the operator installs the helper and a narrow `sudoers.d` rule.
- Adding a new containment capability requires an explicit typed schema, deterministic corroboration rule, and rollback handler.
