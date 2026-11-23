#!/usr/bin/env bash
# ==============================================================================
# Generates the Twingate Connector (Exit) add-on, twingate-connector-exit/,
# from the Twingate Connector add-on, twingate-connector/.
#
# A Twingate Connector belongs to exactly one Remote Network, and Home
# Assistant installs each add-on (slug) only once. To run a second Connector
# on the same device, for an exit network or any other second Remote Network,
# this repository has a second add-on. The Supervisor builds each add-on from
# its own folder only, so the second add-on cannot use the first one's files:
# it is a copy, made by this script. Do not edit twingate-connector-exit/ by
# hand: change twingate-connector/ (or the differences below) and run this
# script.
#
# The copy has the files of twingate-connector/ that Git tracks or would add
# (ignored files are left out), with these differences only:
#   config.yml    name, description, slug, ingress_port, panel_icon and, if
#                 set, panel_title; image is removed if set. The Web UI takes
#                 its name, slug and port from config.yml (connector_ui.py).
#   README.md     the title and a paragraph on what the add-on is for
#   DOCS.md       the title, a section on what the add-on is for, the Web
#                 UI's port and the example host name
#   GENERATED.md  only in the copy: says that the folder is generated
# Every text that is replaced must be found exactly as often as expected, so
# that a change in twingate-connector/ cannot drop a difference unnoticed.
#
# Usage:
#   scripts/sync-connector-exit.sh          writes twingate-connector-exit/
#   scripts/sync-connector-exit.sh --check  writes nothing; prints the
#       differences and exits with 1 when twingate-connector-exit/ (its files
#       and their modes in Git) is not what this script writes. Used by CI.
# ==============================================================================
set -o errexit -o nounset -o pipefail

readonly SOURCE="twingate-connector"
readonly TARGET="twingate-connector-exit"
readonly NAME="Twingate Connector (Exit)"
readonly SLUG="${TARGET}"
readonly DESCRIPTION="Connector for Twingate, for an exit network or another Remote Network"
readonly INGRESS_PORT=8102
readonly PANEL_ICON="mdi:earth-arrow-right"

usage() {
    echo "Usage: $0 [--check]"
}

fail() {
    echo "sync-connector-exit: $*" >&2
    exit 1
}

# ------------------------------------------------------------------------------
# Editing the copy
# ------------------------------------------------------------------------------

# Replaces the text OLD with NEW in FILE, both taken literally. With COUNT a
# number, OLD may be part of a line and must occur exactly COUNT times; with
# COUNT "line", OLD must be a whole line, exactly once.
replace() { # FILE COUNT OLD NEW
    local file="$1"
    OLD="$3" NEW="$4" COUNT="$2" LABEL="${file#"${WORK}"/*/}" awk '
        BEGIN {
            old = ENVIRON["OLD"]
            new = ENVIRON["NEW"]
            count = ENVIRON["COUNT"]
            found = 0
        }
        count == "line" {
            if ($0 == old) {
                print new
                found++
            } else {
                print
            }
            next
        }
        {
            rest = $0
            line = ""
            while ((at = index(rest, old)) > 0) {
                line = line substr(rest, 1, at - 1) new
                rest = substr(rest, at + length(old))
                found++
            }
            print line rest
        }
        END {
            want = (count == "line") ? 1 : count + 0
            if (found != want) {
                printf "sync-connector-exit: %s: expected \"%s\" %d time(s), found it %d time(s)\n",
                    ENVIRON["LABEL"], old, want, found > "/dev/stderr"
                exit 1
            }
        }
    ' "${file}" >"${file}.new" || exit 1
    # Writing into the file keeps its mode.
    cat "${file}.new" >"${file}"
    rm -f "${file}.new"
}

# Edits the top-level key KEY of the YAML file FILE, whose value must be on
# the key's line. ACTION "set" sets it to VALUE (written as is, with quotes
# where needed) and fails when the key is missing, "set-if-present" sets it
# only if it is there, and "delete" removes it if it is there.
edit_key() { # FILE ACTION KEY [VALUE]
    local file="$1"
    ACTION="$2" KEY="$3" VALUE="${4-}" LABEL="${file#"${WORK}"/*/}" awk '
        BEGIN {
            action = ENVIRON["ACTION"]
            key = ENVIRON["KEY"] ":"
            found = 0
            bad = 0
            after_key = 0
        }
        # An indented line right after the key continues its value.
        after_key && /^[ \t]/ { bad = 1 }
        { after_key = 0 }
        substr($0, 1, length(key)) == key && substr($0, length(key) + 1) ~ /^([ \t]|$)/ {
            found++
            after_key = 1
            if (substr($0, length(key) + 1) !~ /^[ \t]+[^ \t|>]/) {
                bad = 1
            }
            if (action != "delete") {
                print key " " ENVIRON["VALUE"]
            }
            next
        }
        { print }
        END {
            if (bad || found > 1 || (found == 0 && action == "set")) {
                printf "sync-connector-exit: %s: cannot %s %s: found %d time(s), or its value is not on its line\n",
                    ENVIRON["LABEL"], action, ENVIRON["KEY"], found > "/dev/stderr"
                exit 1
            }
        }
    ' "${file}" >"${file}.new" || exit 1
    cat "${file}.new" >"${file}"
    rm -f "${file}.new"
}

readme_intro() {
    cat <<'EOF'
A second Twingate Connector on the same Home Assistant, next to the Twingate Connector add-on: for an exit network or any other second Remote Network. A Connector belongs to exactly one Remote Network, and Home Assistant installs each add-on only once, so a second Remote Network needs this second add-on. It needs its own Connector tokens, created in that other Remote Network. Otherwise it is identical to the Twingate Connector add-on.
EOF
}

docs_intro() {
    cat <<'EOF'
## What this add-on is for

This add-on runs a second Twingate Connector on the same Home Assistant,
next to the Twingate Connector add-on: for an exit network, or for any other
second Remote Network. A Connector belongs to exactly one Remote Network, and
Home Assistant installs each add-on only once, so a second Remote Network
needs this second add-on.

- In the Twingate Admin Console, add a new Connector to the other Remote
  Network and generate its own `access token` and `refresh token` (see
  [How to use](#how-to-use)). Do not reuse the tokens of the Connector in
  the Twingate Connector add-on.
- `network` is the same Twingate network name as in the Twingate Connector
  add-on. The tokens decide which Remote Network the Connector belongs to.
- For an exit network, follow Twingate's
  [exit network documentation](https://www.twingate.com/docs/exit-networks).

Otherwise this add-on is identical to the Twingate Connector add-on, and the
rest of this documentation applies to it as well. It has its own
configuration, log and Web UI.
EOF
}

generated_note() {
    cat <<'EOF'
# Generated folder

This folder, the Twingate Connector (Exit) add-on, is a copy of
[`twingate-connector`](../twingate-connector), made by
[`scripts/sync-connector-exit.sh`](../scripts/sync-connector-exit.sh). Do not
edit it by hand. Change `twingate-connector/` instead (or the script, for
the differences between the two add-ons), then run

    scripts/sync-connector-exit.sh

and commit both folders. The Lint workflow runs
`scripts/sync-connector-exit.sh --check`, which fails when this folder is not
what the script writes. The script lists the differences.
EOF
}

# ------------------------------------------------------------------------------
# Files
# ------------------------------------------------------------------------------

# Copies the files of FOLDER (relative to the repository) that Git tracks or
# would add into DEST/FOLDER, with their modes.
copy_folder() { # FOLDER DEST
    local list="${WORK}/files"
    local path
    git -C "${ROOT}" ls-files -z --cached --others --exclude-standard -- "$1/" >"${list}"
    while IFS= read -r -d '' path; do
        # A deleted file stays in Git's list until the deletion is staged.
        if [[ -f "${ROOT}/${path}" ]]; then
            mkdir -p "$2/${path%/*}"
            cp -p "${ROOT}/${path}" "$2/${path}"
        fi
    done <"${list}"
}

# Writes the Twingate Connector (Exit) add-on into DEST/twingate-connector-exit.
generate() { # DEST
    local dest="$1/${TARGET}"
    local config="${dest}/config.yml"
    local intro

    copy_folder "${SOURCE}" "${WORK}/source"
    [[ -f "${WORK}/source/${SOURCE}/config.yml" ]] || fail "${SOURCE}/config.yml not found"
    mv "${WORK}/source/${SOURCE}" "${dest}"

    edit_key "${config}" set name "\"${NAME}\""
    edit_key "${config}" set description "\"${DESCRIPTION}\""
    edit_key "${config}" set slug "\"${SLUG}\""
    edit_key "${config}" set ingress_port "${INGRESS_PORT}"
    edit_key "${config}" set panel_icon "${PANEL_ICON}"
    edit_key "${config}" set-if-present panel_title "\"${NAME}\""
    # Home Assistant builds the copy on the device; an image name would be
    # the main add-on's.
    edit_key "${config}" delete image

    intro=$(readme_intro)
    replace "${dest}/README.md" line "# Home Assistant Add-on: Twingate Connector" \
        "# Home Assistant Add-on: ${NAME}"$'\n\n'"${intro}"

    intro=$(docs_intro)
    replace "${dest}/DOCS.md" line "# Home Assistant Add-on: Twingate Connector add-on" \
        "# Home Assistant Add-on: ${NAME} add-on"$'\n\n'"${intro}"
    replace "${dest}/DOCS.md" 1 "| 8101/tcp |" "| ${INGRESS_PORT}/tcp |"
    replace "${dest}/DOCS.md" 1 "\`local-twingate-connector\`" "\`local-${SLUG}\`"

    generated_note >"${dest}/GENERATED.md"
}

# Prints "PATH<TAB>MODE" for each file of FOLDER in Git's index, PATH
# relative to FOLDER.
git_modes() { # FOLDER
    git -C "${ROOT}" ls-files --stage -- "$1/" >"${WORK}/stage"
    awk -v prefix="$1/" '{
        tab = index($0, "\t")
        print substr($0, tab + 1 + length(prefix)) "\t" $1
    }' "${WORK}/stage"
}

# Prints a line for each file whose mode in Git differs between the two
# folders, and returns 1 if there is one. Files not in Git are skipped.
compare_modes() {
    git_modes "${SOURCE}" >"${WORK}/source-modes"
    git_modes "${TARGET}" >"${WORK}/target-modes"
    awk -F '\t' -v source="${SOURCE}" -v target="${TARGET}" '
        NR == FNR {
            mode[$1] = $2
            next
        }
        ($1 in mode) && mode[$1] != $2 {
            chmod = (mode[$1] == "100755") ? "+x" : "-x"
            printf "%s/%s has mode %s in Git, %s/%s has %s: git update-index --chmod=%s %s/%s\n",
                target, $1, $2, source, $1, mode[$1], chmod, target, $1
            differ = 1
        }
        END { exit differ ? 1 : 0 }
    ' "${WORK}/source-modes" "${WORK}/target-modes"
}

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------

check=false
case "$#:${1-}" in
    0:) ;;
    1:--check) check=true ;;
    1:-h | 1:--help)
        usage
        exit 0
        ;;
    *)
        usage >&2
        exit 2
        ;;
esac

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
readonly ROOT
git -C "${ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1 ||
    fail "${ROOT} is not a Git work tree"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/sync-connector-exit.XXXXXX")
readonly WORK
trap 'rm -rf "${WORK}"' EXIT

mkdir "${WORK}/generated" "${WORK}/committed"
generate "${WORK}/generated"

if [[ "${check}" == false ]]; then
    rm -rf "${ROOT:?}/${TARGET}"
    cp -Rp "${WORK}/generated/${TARGET}" "${ROOT}/${TARGET}"
    echo "Wrote ${TARGET}/ from ${SOURCE}/."
    # compare_modes reports the differences through its return value.
    # shellcheck disable=SC2310
    if ! compare_modes; then
        echo "Set these file modes in Git before you commit (see above)."
    fi
    exit 0
fi

status=0
copy_folder "${TARGET}" "${WORK}/committed"
if ! (cd "${WORK}" && diff -r -u -N "committed/${TARGET}" "generated/${TARGET}"); then
    status=1
fi
# shellcheck disable=SC2310
if ! compare_modes; then
    status=1
fi
if [[ "${status}" -ne 0 ]]; then
    fail "${TARGET}/ is not what this script writes from ${SOURCE}/." \
        "Run scripts/sync-connector-exit.sh, set the file modes shown above (if any) and commit the result."
fi
echo "${TARGET}/ is up to date with ${SOURCE}/."
