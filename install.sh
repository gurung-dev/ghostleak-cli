#!/bin/sh
# Optional launcher install for GhostLeak CLI.
# Termux: $PREFIX/bin/ghostleak
# Linux and macOS: ~/.local/bin/ghostleak
# The clone stays where it is; the wrapper calls python3 on ghostleak.py.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")" && pwd)

if [ -n "${PREFIX:-}" ] && [ -d "${PREFIX}/bin" ]; then
    BINDIR="${PREFIX}/bin"
else
    BINDIR="${HOME}/.local/bin"
    mkdir -p "${BINDIR}"
fi

DEST="${BINDIR}/ghostleak"

cat > "${DEST}" << EOF
#!/bin/sh
exec python3 "${ROOT}/ghostleak.py" "\$@"
EOF

chmod +x "${DEST}" "${ROOT}/ghostleak.py"

printf '%s\n' "Installed ${DEST}"
printf '%s\n' "Wrapper runs ${ROOT}/ghostleak.py (keep this clone in place)."

case ":${PATH}:" in
    *":${BINDIR}:"*) ;;
    *) printf '%s\n' "Add to PATH: export PATH=\"${BINDIR}:\$PATH\"" ;;
esac
