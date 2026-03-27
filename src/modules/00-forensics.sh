#!/usr/bin/env bash

run_module_00() {
    section 0 "MOD0_NAME"

    if ! should_run_module 0; then
        info "$(msg NOT_APPLICABLE)"
        return
    fi

    # --- LevelDB Check ---
    info "$(msg FORENSICS_CHECKING)"
    if [[ -n "$LEVELDB_MATCHES" ]]; then
        error "$(msg FORENSICS_FOUND)"
        echo "$LEVELDB_MATCHES" | tee -a "$LOG_FILE"
    elif [[ -n "$(get_apifox_data_dir)" ]]; then
        info "$(msg FORENSICS_CLEAN)"
    else
        warn "$(msg FORENSICS_NO_DIR)"
    fi

    # --- Version Check ---
    local apifox_ver
    apifox_ver="$(get_apifox_version)"
    if [[ -n "$apifox_ver" ]]; then
        if [[ "$(printf '%s\n' "$FIX_VERSION" "$apifox_ver" | sort -V | head -1)" != "$FIX_VERSION" ]]; then
            warn "$(msg FORENSICS_VERSION_WARN)"
        fi
    fi

    # --- Hosts Block (all malicious domains) ---
    local unblocked_domains
    unblocked_domains="$(get_unblocked_c2_domains)"
    local hosts_file
    hosts_file="$(get_hosts_file)"

    if [[ -z "$unblocked_domains" ]]; then
        log "$(msg FORENSICS_HOSTS_EXISTS)"
    else
        local unblocked_count
        unblocked_count="$(echo "$unblocked_domains" | wc -l | tr -d ' ')"
        if [[ "$DRY_RUN" == true ]]; then
            info "$(msg DRY_RUN_PREFIX): add ${unblocked_count} malicious domains to $hosts_file"
            echo "$unblocked_domains" | while IFS= read -r d; do
                info "  127.0.0.1 $d"
            done
        else
            if [[ "$YES_MODE" == true ]]; then
                local answer="Y"
            else
                info "$(msg FORENSICS_HOSTS_PARTIAL)"
                echo "$unblocked_domains" | while IFS= read -r d; do
                    echo "  $d"
                done
                read -r -p "$(msg FORENSICS_HOSTS_PROMPT) " answer || true
            fi
            case "${answer:-Y}" in
                n|N) warn "$(msg SKIPPED)" ;;
                *)
                    if [[ "$OS_TYPE" == "windows" ]]; then
                        # On Windows (Git Bash), writing to hosts requires elevated privileges
                        # Try direct write; if it fails, instruct user
                        local hosts_content=""
                        echo "$unblocked_domains" | while IFS= read -r d; do
                            [[ -z "$d" ]] && continue
                            if echo "127.0.0.1 $d" >> "$hosts_file" 2>/dev/null; then
                                true
                            else
                                warn "$(msg FORENSICS_HOSTS_WIN_ADMIN)"
                                warn "  127.0.0.1 $d"
                            fi
                        done
                    else
                        echo "$unblocked_domains" | while IFS= read -r d; do
                            [[ -z "$d" ]] && continue
                            echo "127.0.0.1 $d" | sudo tee -a "$hosts_file" > /dev/null
                        done
                    fi
                    log "$(msg FORENSICS_HOSTS_ADDED)"
                    ;;
            esac
        fi
    fi
}
