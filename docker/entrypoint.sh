#!/bin/bash
# The target container is started as uid 10001 with every capability dropped.
# That process cannot chown or switch user, so this path only sets the mask
# and runs the command. A root start (manual) still drops to the sandbox user.
set -euo pipefail
umask 022
if [ "$(id -u)" -eq 0 ]; then
  mkdir -p /work /home/sandbox /tmp
  chown sandbox:sandbox /work /home/sandbox
  chmod 777 /out /tmp
  exec runuser -u sandbox -- "$@"
fi
exec "$@"
