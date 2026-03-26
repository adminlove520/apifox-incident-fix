#!/usr/bin/env bash

# --- Platform Detection ---
# OS_TYPE can be overridden via environment variable (useful for testing)
if [[ -z "${OS_TYPE:-}" ]]; then
    case "$(uname -s)" in
        Darwin) OS_TYPE="macos" ;;
        Linux)  OS_TYPE="linux" ;;
        *)      OS_TYPE="unknown" ;;
    esac
fi

OS_VERSION="${OS_VERSION:-$(uname -sr)}"

# --- Tool Detection ---
HAS_GH=false
HAS_DOCKER=false
HAS_KUBECTL=false
HAS_PGREP=false
HAS_SECURITY=false

# --- Apifox Process Pattern ---
# Matches: Apifox.app (macOS), Apifox Electron helpers (--type=), /opt/Apifox/apifox (Linux binary)
# Uses [A] trick to exclude the grep/pgrep command itself from results
APIFOX_PROC_PATTERN='[A]pifox\.app|[A]pifox.*--type=|/[Aa]pifox/[Aa]pifox'

command -v gh       &>/dev/null && HAS_GH=true
command -v docker   &>/dev/null && HAS_DOCKER=true
command -v kubectl  &>/dev/null && HAS_KUBECTL=true
command -v pgrep    &>/dev/null && HAS_PGREP=true
command -v security &>/dev/null && HAS_SECURITY=true

# --- Apifox Data Directory ---
get_apifox_data_dir() {
    if [[ "$OS_TYPE" == "macos" ]]; then
        echo "$HOME/Library/Application Support/apifox"
    else
        if [[ -d "$HOME/.config/apifox" ]]; then
            echo "$HOME/.config/apifox"
        elif [[ -d "$HOME/.local/share/apifox" ]]; then
            echo "$HOME/.local/share/apifox"
        else
            echo ""
        fi
    fi
}

# --- Apifox Version Detection ---
get_apifox_version() {
    local data_dir
    data_dir="$(get_apifox_data_dir)"
    if [[ -z "$data_dir" ]]; then
        echo ""
        return
    fi

    local app_paths=()
    if [[ "$OS_TYPE" == "macos" ]]; then
        app_paths+=("/Applications/Apifox.app/Contents/Resources/app/package.json")
    else
        # Linux: check common install locations
        app_paths+=(
            "/opt/Apifox/resources/app/package.json"
            "/opt/apifox/resources/app/package.json"
            "$HOME/.local/share/apifox/resources/app/package.json"
            "/usr/lib/apifox/resources/app/package.json"
            "/usr/share/apifox/resources/app/package.json"
        )
        # Also check snap and flatpak
        local snap_path
        snap_path="$(find /snap/apifox -name "package.json" -path "*/resources/app/*" 2>/dev/null | head -1)"
        [[ -n "$snap_path" ]] && app_paths+=("$snap_path")
    fi

    for app_path in "${app_paths[@]}"; do
        if [[ -f "$app_path" ]]; then
            grep -o '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$app_path" 2>/dev/null | head -1 | grep -o '"[^"]*"$' | tr -d '"' || true
            return
        fi
    done
    echo ""
}

# --- SSH Key Scan ---
scan_ssh_keys() {
    local keys=()
    if [[ -d "$HOME/.ssh" ]]; then
        while IFS= read -r -d '' f; do
            local basename
            basename="$(basename "$f")"
            case "$basename" in
                known_hosts*|config*|authorized_keys*|*.pub|*.bak|*.backup|compromised_backup*|*.old) continue ;;
            esac
            # Detect private keys by:
            # 1. PEM header (OpenSSH, RSA, EC, ENCRYPTED, DSA, etc.)
            # 2. OpenSSH binary format magic bytes ("openssh-key-v1")
            # 3. Filename heuristic for common key names without extension
            local is_key=false
            if head -c 256 "$f" 2>/dev/null | grep -qE 'BEGIN .*(PRIVATE KEY|OPENSSH PRIVATE)'; then
                is_key=true
            elif head -c 32 "$f" 2>/dev/null | grep -q "openssh-key-v1"; then
                is_key=true
            elif [[ "$basename" =~ ^id_ ]] && [[ ! "$basename" =~ \. ]]; then
                # Common pattern: id_rsa, id_ed25519, id_ecdsa (no extension = likely private key)
                is_key=true
            fi
            if $is_key; then
                keys+=("$f")
            fi
        done < <(find "$HOME/.ssh" -maxdepth 1 -type f -print0 2>/dev/null)
    fi
    if [[ ${#keys[@]} -gt 0 ]]; then
        printf '%s\n' "${keys[@]}"
    fi
}

# --- SSH Config Host Mapping ---
get_hosts_for_key() {
    local key_path="$1"
    local config="$HOME/.ssh/config"
    if [[ ! -f "$config" ]]; then
        return
    fi
    awk -v key="$key_path" '
        /^Host / { host = $2 }
        /IdentityFile/ && index($0, key) { print host }
    ' "$config"
}

# --- Shell History Scan ---
scan_history_files() {
    local files=()
    [[ -f "$HOME/.zsh_history" ]]   && files+=("$HOME/.zsh_history")
    [[ -f "$HOME/.bash_history" ]]  && files+=("$HOME/.bash_history")
    [[ -f "$HOME/.local/share/fish/fish_history" ]] && files+=("$HOME/.local/share/fish/fish_history")
    if [[ ${#files[@]} -gt 0 ]]; then
        printf '%s\n' "${files[@]}"
    fi
}

has_sensitive_history() {
    local pattern="token|secret|password|key=|credential|auth"
    if [[ -n "${EXTRA_PATTERNS:-}" ]]; then
        pattern="${pattern}|${EXTRA_PATTERNS}"
    fi
    local found=false
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        if grep -qiE "$pattern" "$f" 2>/dev/null; then
            found=true
            break
        fi
    done <<< "$(scan_history_files)"
    $found
}

# --- Docker Registry Scan ---
scan_docker_registries() {
    local config="$HOME/.docker/config.json"
    if [[ ! -f "$config" ]]; then
        return
    fi
    # Extract registry keys directly under "auths" with a small JSON-aware scanner.
    # This avoids false negatives on pretty-printed configs and false positives on nested fields.
    awk '
        BEGIN {
            depth = 0
            in_auths = 0
            auths_depth = 0
            in_string = 0
            escaped = 0
            token = ""
            last_string = ""
            pending_registry = ""
            expect_auths_object = 0
        }
        {
            line = $0 "\n"
            for (i = 1; i <= length(line); i++) {
                c = substr(line, i, 1)

                if (in_string) {
                    if (escaped) {
                        token = token c
                        escaped = 0
                        continue
                    }
                    if (c == "\\") {
                        token = token c
                        escaped = 1
                        continue
                    }
                    if (c == "\"") {
                        in_string = 0
                        last_string = token
                        token = ""
                    } else {
                        token = token c
                    }
                    continue
                }

                if (c == "\"") {
                    in_string = 1
                    token = ""
                    continue
                }

                if (c ~ /[[:space:]]/) {
                    continue
                }

                if (c == ":") {
                    if (!in_auths && depth == 1 && last_string == "auths") {
                        expect_auths_object = 1
                    } else if (in_auths && depth == auths_depth && last_string != "") {
                        pending_registry = last_string
                    }
                    last_string = ""
                    continue
                }

                if (c == "{") {
                    depth++
                    if (expect_auths_object) {
                        in_auths = 1
                        auths_depth = depth
                        expect_auths_object = 0
                    } else if (in_auths && pending_registry != "" && depth == auths_depth + 1) {
                        if (pending_registry ~ /[.\/:]/) {
                            print pending_registry
                        }
                        pending_registry = ""
                    }
                    continue
                }

                if (c == "}") {
                    if (in_auths && depth == auths_depth) {
                        in_auths = 0
                        auths_depth = 0
                    }
                    depth--
                    pending_registry = ""
                    last_string = ""
                    continue
                }

                if (c == ",") {
                    pending_registry = ""
                    last_string = ""
                }
            }
        }
    ' "$config"
}

# --- .env File Scan ---
scan_env_files() {
    local dirs=("$HOME/Projects" "$HOME/Code" "$HOME/Work" "$HOME/Desktop" "$HOME/code" "$HOME/projects" "$HOME/dev" "$HOME/Developer" "$HOME/src")

    if [[ -n "${SCAN_DIRS:-}" ]]; then
        IFS=',' read -ra EXTRA_DIRS <<< "$SCAN_DIRS"
        dirs+=("${EXTRA_DIRS[@]}")
    fi

    local existing_dirs=()
    for d in "${dirs[@]}"; do
        [[ -d "$d" ]] && existing_dirs+=("$d")
    done

    if [[ ${#existing_dirs[@]} -eq 0 ]]; then
        return
    fi

    find "${existing_dirs[@]}" -maxdepth 5 \
        \( -name ".env" -o -name ".env.*" -o -name "*.key" -o -name "*.pem" \) \
        2>/dev/null || true
}

# --- Hosts Check ---
# Matches 127.0.0.1, 0.0.0.0, ::1 with optional trailing comments
is_c2_blocked() {
    grep -qE "^[[:space:]]*(127\.0\.0\.1|0\.0\.0\.0|::1)[[:space:]]+([^#]*[[:space:]]+)*${C2_DOMAIN}([[:space:]]|$)" /etc/hosts 2>/dev/null
}

# --- Module Applicability Array ---
declare -a MODULE_APPLICABLE
for i in {0..9}; do
    MODULE_APPLICABLE[$i]=true
done

# --- Full System Scan & Report ---
run_system_scan() {
    echo ""
    echo "============================================"
    info "  $(msg SCAN_TITLE)"
    echo "============================================"

    # Platform
    printf "  %-20s %s\n" "$(msg SCAN_PLATFORM):" "$OS_VERSION"

    # Apifox process — match Apifox.app or Apifox binary, exclude this script and grep
    local apifox_pids=""
    if $HAS_PGREP; then
        apifox_pids="$(pgrep -f "$APIFOX_PROC_PATTERN" 2>/dev/null || true)"
    fi
    if [[ -n "$apifox_pids" ]]; then
        printf "  %-20s ${RED}%s (PID: %s)${NC}\n" "$(msg SCAN_APIFOX_PROC):" "$(msg SCAN_RUNNING)" "$(echo "$apifox_pids" | tr '\n' ',' | sed 's/,$//')"
        MODULE_APPLICABLE[1]=true
    else
        printf "  %-20s %s\n" "$(msg SCAN_APIFOX_PROC):" "$(msg SCAN_NOT_RUNNING)"
        MODULE_APPLICABLE[1]=false
    fi

    # LevelDB check
    local data_dir
    data_dir="$(get_apifox_data_dir)"
    local leveldb_dir="${data_dir:+${data_dir}/Local Storage/leveldb}"
    LEVELDB_MATCHES=""
    if [[ -n "$leveldb_dir" && -d "$leveldb_dir" ]]; then
        LEVELDB_MATCHES="$(grep -arlE "rl_mc|rl_headers" "$leveldb_dir" 2>/dev/null || true)"
        if [[ -n "$LEVELDB_MATCHES" ]]; then
            printf "  %-20s ${RED}%s${NC}\n" "$(msg SCAN_LEVELDB):" "$(msg SCAN_MALICIOUS)"
        else
            printf "  %-20s %s\n" "$(msg SCAN_LEVELDB):" "$(msg SCAN_CLEAN)"
        fi
    else
        printf "  %-20s %s\n" "$(msg SCAN_LEVELDB):" "$(msg SCAN_NOT_FOUND)"
    fi

    # Version check
    local apifox_ver
    apifox_ver="$(get_apifox_version)"
    if [[ -n "$apifox_ver" ]]; then
        if [[ "$(printf '%s\n' "$FIX_VERSION" "$apifox_ver" | sort -V | head -1)" != "$FIX_VERSION" ]]; then
            printf "  %-20s ${RED}%s (%s ${FIX_VERSION}+)${NC}\n" "$(msg SCAN_VERSION):" "$apifox_ver" "$(msg SCAN_OUTDATED)"
        else
            printf "  %-20s %s\n" "$(msg SCAN_VERSION):" "$apifox_ver"
        fi
    fi

    # Hosts block
    if is_c2_blocked; then
        printf "  %-20s ${GREEN}%s${NC}\n" "$(msg SCAN_HOSTS):" "${C2_DOMAIN} $(msg SCAN_HOSTS_BLOCKED)"
    else
        printf "  %-20s ${RED}%s${NC}\n" "$(msg SCAN_HOSTS):" "${C2_DOMAIN} $(msg SCAN_HOSTS_NOT_BLOCKED)"
    fi

    echo ""
    printf "  ${BOLD}%s:${NC}\n" "$(msg SCAN_CREDS_TITLE)"

    # SSH
    SSH_KEYS="$(scan_ssh_keys)"
    local ssh_count=0
    if [[ -n "$SSH_KEYS" ]]; then
        ssh_count="$(echo "$SSH_KEYS" | wc -l | tr -d ' ')"
    fi
    if [[ "$ssh_count" -gt 0 ]]; then
        local ssh_names
        ssh_names="$(echo "$SSH_KEYS" | xargs -I{} basename {} | tr '\n' ', ' | sed 's/,$//')"
        printf "    %-18s %s (%d keys)\n" "$(msg SCAN_SSH):" "$ssh_names" "$ssh_count"
        MODULE_APPLICABLE[2]=true
    else
        printf "    %-18s %s\n" "$(msg SCAN_SSH):" "$(msg SCAN_NOT_FOUND)"
        MODULE_APPLICABLE[2]=false
    fi

    # GitHub
    if $HAS_GH; then
        local gh_user
        gh_user="$(gh auth status 2>&1 | grep -oE 'account [^ ]+' | head -1 | awk '{print $2}' || true)"
        if [[ -n "$gh_user" ]]; then
            printf "    %-18s logged in as %s\n" "$(msg SCAN_GITHUB):" "$gh_user"
            MODULE_APPLICABLE[4]=true
        else
            printf "    %-18s not logged in\n" "$(msg SCAN_GITHUB):"
            MODULE_APPLICABLE[4]=false
        fi
    else
        printf "    %-18s not installed\n" "$(msg SCAN_GITHUB):"
        MODULE_APPLICABLE[4]=false
    fi

    # K8s
    if [[ -f "$HOME/.kube/config" ]] && $HAS_KUBECTL; then
        local k8s_ctx
        k8s_ctx="$(kubectl config current-context 2>/dev/null || echo 'unknown')"
        printf "    %-18s ~/.kube/config (context: %s)\n" "$(msg SCAN_K8S):" "$k8s_ctx"
        MODULE_APPLICABLE[5]=true
    else
        printf "    %-18s %s\n" "$(msg SCAN_K8S):" "$(msg SCAN_NOT_FOUND)"
        MODULE_APPLICABLE[5]=false
    fi

    # Docker
    DOCKER_REGISTRIES="$(scan_docker_registries)"
    local docker_count=0
    if [[ -n "$DOCKER_REGISTRIES" ]]; then
        docker_count="$(echo "$DOCKER_REGISTRIES" | wc -l | tr -d ' ')"
    fi
    if [[ "$docker_count" -gt 0 ]]; then
        printf "    %-18s %d registries\n" "$(msg SCAN_DOCKER):" "$docker_count"
        MODULE_APPLICABLE[6]=true
    else
        printf "    %-18s %s\n" "$(msg SCAN_DOCKER):" "$(msg SCAN_NOT_FOUND)"
        MODULE_APPLICABLE[6]=false
    fi

    # History
    if has_sensitive_history; then
        printf "    %-18s ${YELLOW}%s${NC}\n" "$(msg SCAN_HISTORY):" "$(msg SCAN_HISTORY_SENSITIVE)"
        MODULE_APPLICABLE[3]=true
    else
        printf "    %-18s %s\n" "$(msg SCAN_HISTORY):" "$(msg SCAN_HISTORY_CLEAN)"
        MODULE_APPLICABLE[3]=false
    fi

    # .env files
    ENV_FILES="$(scan_env_files)"
    local env_count=0
    if [[ -n "$ENV_FILES" ]]; then
        env_count="$(echo "$ENV_FILES" | wc -l | tr -d ' ')"
    fi
    if [[ "$env_count" -gt 0 ]]; then
        printf "    %-18s %d found\n" "$(msg SCAN_ENV):" "$env_count"
        MODULE_APPLICABLE[8]=true
    else
        printf "    %-18s %s\n" "$(msg SCAN_ENV):" "$(msg SCAN_NOT_FOUND)"
        MODULE_APPLICABLE[8]=false
    fi

    # Module 0 (forensics) always applicable
    MODULE_APPLICABLE[0]=true
    # Module 7 (keychain) only on macOS
    if [[ "$OS_TYPE" == "macos" ]]; then
        MODULE_APPLICABLE[7]=true
    else
        MODULE_APPLICABLE[7]=false
    fi
    # Module 9 (audit) always applicable
    MODULE_APPLICABLE[9]=true

    # Module summary
    echo ""
    printf "  ${BOLD}%s:${NC}\n" "$(msg SCAN_MODULES_TITLE)"
    local mod_names=("MOD0_NAME" "MOD1_NAME" "MOD2_NAME" "MOD3_NAME" "MOD4_NAME" "MOD5_NAME" "MOD6_NAME" "MOD7_NAME" "MOD8_NAME" "MOD9_NAME")
    for i in "${!mod_names[@]}"; do
        local status_icon status_text
        if ${MODULE_APPLICABLE[$i]}; then
            status_icon="${GREEN}✓${NC}"
            status_text="$(msg SCAN_APPLICABLE)"
        else
            status_icon="${YELLOW}—${NC}"
            status_text="$(msg SCAN_SKIP)"
        fi
        printf "    [%d] %-35s %b %s\n" "$i" "$(msg "${mod_names[$i]}")" "$status_icon" "$status_text"
    done

    echo ""
}

# --- Module Selection Prompt ---
prompt_module_selection() {
    if [[ -n "$SELECTED_MODULES" ]]; then
        return 0
    fi

    if [[ "$YES_MODE" == true ]]; then
        return 0
    fi

    read -r -p "$(msg PROCEED_ALL) " choice || true
    case "${choice:-Y}" in
        n|N)
            log "$(msg USER_QUIT) $LOG_FILE"
            exit 0
            ;;
        select|SELECT)
            read -r -p "$(msg SELECT_PROMPT) " SELECTED_MODULES
            validate_selected_modules
            ;;
        *)
            # Run all applicable
            ;;
    esac
}
