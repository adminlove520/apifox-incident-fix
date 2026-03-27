#!/usr/bin/env bash

# --- Check if module actually ran (selected + applicable) ---
module_ran() {
    local mod_num="$1"
    should_run_module "$mod_num" && ${MODULE_APPLICABLE[$mod_num]}
}

# --- Summary & Manual Checklist ---
print_summary() {
    echo ""
    echo "============================================================"
    log "$(msg COMPLETE)"
    echo "============================================================"
    echo ""
    echo "$(msg LOG_SAVED): $LOG_FILE"
    echo ""
    echo "$(msg REMAINING)"
    # Dynamic checklist based on what actually ran
    if module_ran 2; then
        echo "  □ $(msg SSH_PUBKEY) → GitHub / GitLab"
    fi
    if module_ran 4; then
        echo "  □ $(msg GITHUB_MANUAL_TOKENS)"
        echo "  □ $(msg GITHUB_MANUAL_SESSIONS)"
    fi
    if module_ran 3; then
        echo "  □ Rotate leaked tokens (ngrok, etc.)"
    fi
    if module_ran 5; then
        echo "  □ $(msg K8S_MANUAL)"
    fi
    if module_ran 6; then
        echo "  □ $(msg DOCKER_MANUAL)"
    fi
    if module_ran 7; then
        echo "  □ $(msg KEYCHAIN_MANUAL)"
    fi
    if module_ran 10; then
        echo "  □ $(msg NPM_MANUAL)"
    fi
    echo ""
}

# --- Main Execution ---
main() {
    # Handle help flag
    if [[ "${SHOW_HELP:-false}" == true ]]; then
        show_help
        exit 0
    fi

    # Validate --modules input early
    validate_selected_modules

    # Banner
    echo "============================================================"
    echo "  $(msg BANNER_TITLE) v${VERSION}"
    echo "  $(date)"
    echo "  $(msg LOG_SAVED): $LOG_FILE"
    echo ""
    echo "  Risk window: ${RISK_START} — ${RISK_END}"
    echo "  Fix version: ${FIX_VERSION}+"
    echo "  Announcement: ${ANNOUNCEMENT_URL}"
    echo "============================================================"

    # System scan
    run_system_scan

    # Module selection
    prompt_module_selection

    # Second confirmation before making real changes
    if [[ "$DRY_RUN" != true && "$YES_MODE" != true ]]; then
        echo ""
        warn "$(msg CONFIRM_WARN)"
        info "$(msg CONFIRM_DRY_RUN_HINT)"
        echo ""
        read -r -p "$(msg CONFIRM_PROMPT) " confirm || true
        case "${confirm:-}" in
            y|Y|yes|YES)
                ;;
            *)
                log "$(msg CONFIRM_ABORTED)"
                exit 0
                ;;
        esac
    fi

    # Execute only selected + applicable modules
    local mod_funcs=(run_module_00 run_module_01 run_module_02 run_module_03 run_module_04 run_module_05 run_module_06 run_module_07 run_module_08 run_module_09 run_module_10 run_module_11)
    for i in "${!mod_funcs[@]}"; do
        if module_ran "$i"; then
            ${mod_funcs[$i]}
        fi
    done

    # Summary
    print_summary
}

main
