# Sandbox Policy

The review harness evaluates every command before execution with
`ReviewExecutionPolicy`.

Denied commands are never executed:

- destructive host operations such as `rm -rf /`, `mkfs`, `dd if=`, `shutdown`, or `reboot`
- pipe-to-shell downloads such as `curl ... | bash` or `wget ... | sh`
- access to `/etc`, `/root`, `~/.ssh`, or `/var/run/docker.sock`
- absolute output paths or output globs containing `../`
- environment keys containing `TOKEN`, `SECRET`, `PASSWORD`, or `API_KEY` unless explicitly whitelisted
- timeouts greater than `max_timeout_sec`

Needs-human-review commands are also not executed:

- network access
- package installation
- unknown executables
- container-to-local fallback records

Only the three documented `python3 scripts/*.py` commands are allowlisted.

