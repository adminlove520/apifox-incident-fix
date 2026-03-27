#!/usr/bin/env bash

run_module_01() {
    section 1 "MOD1_NAME"

    if ! should_run_module 1 || ! ${MODULE_APPLICABLE[1]}; then
        info "$(msg KILL_NONE)"
        return
    fi

    local pids=""
    if [[ "$OS_TYPE" == "windows" ]]; then
        # Use tasklist on Windows (Git Bash)
        if command -v tasklist &>/dev/null; then
            pids="$(tasklist 2>/dev/null | grep -i "Apifox.exe" | awk '{print $2}' | tr '\n' ' ' | sed 's/ $//' || true)"
        fi
    elif $HAS_PGREP; then
        pids="$(pgrep -f "$APIFOX_PROC_PATTERN" 2>/dev/null || true)"
    fi

    if [[ -z "$pids" ]]; then
        log "$(msg KILL_NONE)"
        return
    fi

    warn "$(msg KILL_FOUND)"
    if [[ "$OS_TYPE" == "windows" ]]; then
        tasklist 2>/dev/null | grep -i "Apifox.exe" | tee -a "$LOG_FILE" || true
    else
        ps -p "$(echo "$pids" | tr '\n' ',' | sed 's/,$//')" -o pid,comm 2>/dev/null | tee -a "$LOG_FILE" || true
    fi

    if ! pause; then return; fi

    if [[ "$DRY_RUN" == true ]]; then
        info "$(msg DRY_RUN_PREFIX): kill Apifox processes (PIDs: $(echo "$pids" | tr '\n' ',' | sed 's/,$//'))"
        return
    fi

    if [[ "$OS_TYPE" == "windows" ]]; then
        taskkill /F /IM "Apifox.exe" 2>/dev/null || true
    else
        while IFS= read -r pid; do
            [[ -z "$pid" ]] && continue
            kill "$pid" 2>/dev/null || true
        done <<< "$pids"

        sleep 1

        local remaining
        remaining="$(pgrep -f "$APIFOX_PROC_PATTERN" 2>/dev/null || true)"
        if [[ -n "$remaining" ]]; then
            warn "$(msg KILL_FORCE)"
            while IFS= read -r pid; do
                [[ -z "$pid" ]] && continue
                kill -9 "$pid" 2>/dev/null || true
            done <<< "$remaining"
        fi
    fi

    log "$(msg KILL_DONE)"
}
