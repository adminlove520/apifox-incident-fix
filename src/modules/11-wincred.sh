#!/usr/bin/env bash

run_module_11() {
    section 11 "MOD11_NAME"

    if ! should_run_module 11 || ! ${MODULE_APPLICABLE[11]}; then
        info "$(msg NOT_APPLICABLE)"
        return
    fi

    if [[ "$OS_TYPE" != "windows" ]]; then
        info "$(msg WINCRED_WINDOWS_ONLY)"
        return
    fi

    info "$(msg WINCRED_SEARCHING)"

    # Use cmdkey to list Windows Credential Manager entries
    local creds=""
    if command -v cmdkey &>/dev/null; then
        creds="$(cmdkey /list 2>/dev/null | grep -i "target\|user" | grep -iv "microsoft\|windows\|live\|virtualapp" || true)"
    fi

    local apifox_creds=""
    if [[ -n "$creds" ]]; then
        apifox_creds="$(echo "$creds" | grep -i "apifox" || true)"
    fi

    if [[ -n "$apifox_creds" ]]; then
        warn "$(msg WINCRED_FOUND)"
        echo "$apifox_creds" | tee -a "$LOG_FILE"
        echo ""
        info "$(msg WINCRED_REMOVE_HINT)"
        if [[ "$DRY_RUN" != true ]]; then
            echo "$apifox_creds" | grep -oP '(?<=Target: ).*' | while IFS= read -r target; do
                [[ -z "$target" ]] && continue
                if ! pause; then break; fi
                cmdkey /delete:"$target" 2>/dev/null && log "Removed: $target" || warn "Could not remove: $target"
            done
        fi
    else
        info "$(msg WINCRED_NONE)"
    fi

    # Check Git credentials on Windows
    local git_cred_file="$HOME/.git-credentials"
    if [[ -f "$git_cred_file" ]]; then
        warn "$(msg WINCRED_GIT_CREDS): $git_cred_file"
        echo "  $git_cred_file" >> "$LOG_FILE"
    fi

    echo ""
    manual "$(msg WINCRED_MANUAL)"
}
