#!/usr/bin/env bash

# QBittorrent IP Filter Updater & Manager
# Version: 2.0
# Author: Enhanced by Community
# License: GPL-3.0
# Repository: https://github.com/yourusername/qbittorrent-ipfilter-updater

# Description:
# This script automatically updates and manages IP filters for qBittorrent.
# It downloads and processes multiple blocklists from various sources to create
# a comprehensive IP filter that blocks malicious peers, known bad actors,
# spam sources, and potentially harmful IPs.
#
# Features:
# - Automatic detection of qBittorrent installation (apt, rpm, flatpak)
# - Downloads and processes 40+ blocklists
# - Removes duplicate entries while preserving unique IPs
# - Supports multiple formats (P2P, CIDR, individual IPs)
# - Caches downloads to prevent unnecessary updates
# - Provides detailed statistics and progress information
#
# Usage: ./QT.sh [--force] [--quiet] [--help]
#   --force: Force update even if cache is fresh
#   --quiet: Minimal output
#   --help:  Show this help message

# Function to search for qBittorrent directory if not found in default location
find_qbittorrent_dir() {
    local default_dir="$HOME/.var/app/org.qbittorrent.qBittorrent/data/qBittorrent"
    local fallback_dir="$HOME/.local/share/qBittorrent"
    local script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    if [ -f "$HOME/.var/app/org.qbittorrent.qBittorrent/config/qBittorrent/qBittorrent.conf" ]; then
        local config_path="$HOME/.var/app/org.qbittorrent.qBittorrent/config/qBittorrent/qBittorrent.conf"
        local configured_path=$(grep "^Session\\\\IPFilter=" "$config_path" | cut -d'=' -f2)
        if [ ! -z "$configured_path" ]; then
            echo "$(dirname "$configured_path")"
            return
        fi
    fi

    if [ -d "$default_dir" ]; then
        echo "$default_dir"
    elif [ -d "$fallback_dir" ]; then
        echo "$fallback_dir"
    else
        echo "$script_dir"
    fi
}

# Function to convert CIDR to IP ranges
cidr_to_range() {
    local cidr=$1
    local ip start_ip end_ip bits

    IFS=/ read ip bits <<< "$cidr"
    IFS=. read -r i1 i2 i3 i4 <<< "$ip"

    local mask=$(( 0xFFFFFFFF ^ ((1 << (32 - bits)) - 1) ))
    local ip_num=$(( (i1 << 24) + (i2 << 16) + (i3 << 8) + i4 ))
    local start_ip_num=$(( ip_num & mask ))
    local end_ip_num=$(( start_ip_num | ~mask & 0xFFFFFFFF ))

    printf "%d.%d.%d.%d-%d.%d.%d.%d,1\n" \
        $(( (start_ip_num >> 24) & 0xFF )) $(( (start_ip_num >> 16) & 0xFF )) \
        $(( (start_ip_num >> 8) & 0xFF )) $(( start_ip_num & 0xFF )) \
        $(( (end_ip_num >> 24) & 0xFF )) $(( (end_ip_num >> 16) & 0xFF )) \
        $(( (end_ip_num >> 8) & 0xFF )) $(( end_ip_num & 0xFF ))
}

# Export the function so it's available to subshells
export -f cidr_to_range

# Check for qBittorrent installation and version
check_qbittorrent_installation() {
    local qbt_found=false
    local qbt_version=""
    local install_type=""

    # Check APT installation
    if command -v apt >/dev/null 2>&1; then
        if dpkg -l | grep -q qbittorrent; then
            qbt_version=$(dpkg -l | grep qbittorrent | awk '{print $3}')
            install_type="APT"
            qbt_found=true
        fi
    fi

    # Check RPM installation
    if command -v rpm >/dev/null 2>&1; then
        if rpm -qa | grep -q qbittorrent; then
            qbt_version=$(rpm -qa | grep qbittorrent | awk -F'-' '{print $2}')
            install_type="RPM"
            qbt_found=true
        fi
    fi

    # Check Flatpak installation
    if command -v flatpak >/dev/null 2>&1; then
        if flatpak list | grep -q org.qbittorrent.qBittorrent; then
            qbt_version=$(flatpak info org.qbittorrent.qBittorrent | grep Version | awk '{print $2}')
            install_type="Flatpak"
            qbt_found=true
        fi
    fi

    if [ "$qbt_found" = true ]; then
        echo "qBittorrent detected:"
        echo "- Installation type: $install_type"
        echo "- Version: $qbt_version"
        
        # Check for updates
        case $install_type in
            "APT")
                if apt list --upgradable 2>/dev/null | grep -q qbittorrent; then
                    echo "- Update available through APT"
                    read -p "Would you like to update qBittorrent? [y/N] " -n 1 -r
                    echo
                    if [[ $REPLY =~ ^[Yy]$ ]]; then
                        sudo apt update && sudo apt upgrade qbittorrent -y
                    fi
                fi
                ;;
            "RPM")
                if command -v dnf >/dev/null 2>&1; then
                    if dnf check-update qbittorrent >/dev/null 2>&1; then
                        echo "- Update available through DNF"
                        read -p "Would you like to update qBittorrent? [y/N] " -n 1 -r
                        echo
                        if [[ $REPLY =~ ^[Yy]$ ]]; then
                            sudo dnf update qbittorrent -y
                        fi
                    fi
                fi
                ;;
            "Flatpak")
                if flatpak remote-ls --updates | grep -q org.qbittorrent.qBittorrent; then
                    echo "- Update available through Flatpak"
                    read -p "Would you like to update qBittorrent? [y/N] " -n 1 -r
                    echo
                    if [[ $REPLY =~ ^[Yy]$ ]]; then
                        flatpak update org.qbittorrent.qBittorrent -y
                    fi
                fi
                ;;
        esac
    else
        echo "qBittorrent not found. Please install it first:"
        echo "- APT: sudo apt install qbittorrent"
        echo "- RPM: sudo dnf install qbittorrent"
        echo "- Flatpak: flatpak install flathub org.qbittorrent.qBittorrent"
        exit 1
    fi
}

# Locate the qBittorrent data directory
QBT_DIR=$(find_qbittorrent_dir)

# Check if the qBittorrent directory exists
if [ -z "$QBT_DIR" ]; then
    echo "qBittorrent directory not found."
    exit 1
fi

# Define the blocklist directory and ensure it exists
BLOCKLIST_DIR="$QBT_DIR/BT_backup"
mkdir -p "$BLOCKLIST_DIR"
cd "$BLOCKLIST_DIR" || { echo "Failed to change directory to $BLOCKLIST_DIR."; exit 1; }

# Create cache directory for metadata
CACHE_DIR="$HOME/.cache/qbittorrent_blocklists"
mkdir -p "$CACHE_DIR"

# Function to check if file needs updating using HTTP headers
check_http_headers() {
    local url="$1"
    local local_file="$2"
    local headers_file="$CACHE_DIR/$(echo "$url" | md5sum | cut -d' ' -f1).headers"
    
    # Get remote headers
    if ! curl -sI "$url" > "$headers_file.new" 2>/dev/null; then
        rm -f "$headers_file.new"
        return 2 # Failed to get headers
    fi
    
    # Check if we have previous headers
    if [ -f "$headers_file" ] && [ -f "$local_file" ]; then
        local old_etag=$(grep -i "^ETag:" "$headers_file" | head -n1)
        local new_etag=$(grep -i "^ETag:" "$headers_file.new" | head -n1)
        local old_modified=$(grep -i "^Last-Modified:" "$headers_file" | head -n1)
        local new_modified=$(grep -i "^Last-Modified:" "$headers_file.new" | head -n1)
        
        # If either ETag or Last-Modified matches, file hasn't changed
        if [ -n "$old_etag" ] && [ "$old_etag" = "$new_etag" ] || \
           [ -n "$old_modified" ] && [ "$old_modified" = "$new_modified" ]; then
            mv "$headers_file.new" "$headers_file"
            return 1 # File unchanged
        fi
    fi
    
    mv "$headers_file.new" "$headers_file"
    return 0 # File needs update
}

# Function to check file using checksums
check_checksum() {
    local url="$1"
    local local_file="$2"
    local checksum_file="$CACHE_DIR/$(echo "$url" | md5sum | cut -d' ' -f1).sha256"
    
    # If local file doesn't exist, need to download
    [ ! -f "$local_file" ] && return 0
    
    # Calculate current checksum
    local current_checksum=$(sha256sum "$local_file" | cut -d' ' -f1)
    
    # If we have a stored checksum, compare
    if [ -f "$checksum_file" ]; then
        local stored_checksum=$(cat "$checksum_file")
        if [ "$current_checksum" = "$stored_checksum" ]; then
            return 1 # File unchanged
        fi
    fi
    
    return 0 # File needs update
}

# Function to check file age
check_file_age() {
    local local_file="$1"
    local max_age=$2 # in seconds
    
    # If file doesn't exist, need to download
    [ ! -f "$local_file" ] && return 0
    
    local file_age=$(($(date +%s) - $(stat -c %Y "$local_file")))
    if [ $file_age -lt $max_age ]; then
        return 1 # File is fresh
    fi
    
    return 0 # File needs update
}

# Function to download file with all checks
download_with_checks() {
    local url="$1"
    local output_file="$2"
    local max_age=${3:-86400} # Default to 24 hours
    
    echo "Checking $url..."
    
    # First try HTTP headers
    check_http_headers "$url" "$output_file"
    local header_check=$?
    
    if [ $header_check -eq 2 ]; then
        # Headers check failed, try checksum
        if check_checksum "$url" "$output_file"; then
            # Checksum indicates update needed, check age as last resort
            if ! check_file_age "$output_file" "$max_age"; then
                echo "File is fresh (age check): $output_file"
                return 0
            fi
        else
            echo "File unchanged (checksum check): $output_file"
            return 0
        fi
    elif [ $header_check -eq 1 ]; then
        echo "File unchanged (header check): $output_file"
        return 0
    fi
    
    # Download file
    echo "Downloading $url..."
    if curl -sSL "$url" -o "$output_file.tmp"; then
        mv "$output_file.tmp" "$output_file"
        # Update checksum
        sha256sum "$output_file" | cut -d' ' -f1 > "$CACHE_DIR/$(echo "$url" | md5sum | cut -d' ' -f1).sha256"
        echo "Downloaded new version of $(basename "$output_file")"
        return 0
    else
        rm -f "$output_file.tmp"
        echo "Failed to download $url"
        return 1
    fi
}

# Function to download and process blocklists
download_blocklist() {
    local url=$1
    local output=$2
    
    if ! download_with_checks "$url" "$output" 86400; then
        echo "Failed to download $url. Skipping."
        return 1
    fi
    
    if [[ "$output" == *.gz ]]; then
        gunzip -f "$output" 2>/dev/null || { echo "Invalid gzip format for $output. Skipping."; rm -f "$output"; }
    elif [[ "$output" == *.zip ]]; then
        unzip -o "$output" -d "${output%.zip}" 2>/dev/null || { echo "Invalid zip format for $output. Skipping."; rm -f "$output"; }
        find "${output%.zip}" -type f -name "*.dat" -exec cat {} + >> raw_blocklist.tmp
        rm -r "${output%.zip}" 2>/dev/null
    elif [[ "$output" == *.dat || "$output" == *.txt || "$output" == *.netset || "$output" == *.zone ]]; then
        cat "$output" >> raw_blocklist.tmp
    else
        echo "Unsupported file format: $output. Skipping."
    fi
}

# Function to write IP ranges to file
write_ip_ranges() {
    local output_file="$1"
    local temp_file="$2"
    
    # Write header
    {
        echo "# qBittorrent IP Filter"
        echo "# Updated: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
        echo "# Format: range start-range end, access level"
        echo "# Access level: 0 = allowed, >0 = blocked"
        echo ""
        
        # Convert single IPs and CIDR to ranges and write to file
        while IFS= read -r line; do
            if [[ $line =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(/[0-9]+)?$ ]]; then
                # Single IP or CIDR
                if [[ $line == *"/"* ]]; then
                    # CIDR notation
                    base_ip="${BASH_REMATCH[1]}"
                    cidr="${line#*/}"
                    # Convert CIDR to range
                    IFS=. read -r i1 i2 i3 i4 <<< "$base_ip"
                    ip_int=$(( (i1 << 24) + (i2 << 16) + (i3 << 8) + i4 ))
                    mask=$((0xffffffff << (32 - cidr)))
                    net_start=$((ip_int & mask))
                    net_end=$((net_start | ~mask & 0xffffffff))
                    printf "%d.%d.%d.%d-%d.%d.%d.%d,1\n" \
                        $((net_start >> 24 & 0xff)) $((net_start >> 16 & 0xff)) \
                        $((net_start >> 8 & 0xff)) $((net_start & 0xff)) \
                        $((net_end >> 24 & 0xff)) $((net_end >> 16 & 0xff)) \
                        $((net_end >> 8 & 0xff)) $((net_end & 0xff))
                else
                    # Single IP
                    echo "${line}-${line},1"
                fi
            elif [[ $line =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)-([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
                # Already in range format
                echo "${line},1"
            fi
        done < "$temp_file"
    } > "$output_file"
}

# Function to process a file and extract IPs
process_file() {
    local file="$1"
    local temp_file="$2"
    
    # Handle different file formats
    if [[ "$file" == *.gz ]]; then
        zcat "$file" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?(-([0-9]{1,3}\.){3}[0-9]{1,3})?' >> "$temp_file"
    elif [[ "$file" == *.zip ]]; then
        if [[ -f "blocklist_emule/guarding.p2p" ]]; then
            grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?(-([0-9]{1,3}\.){3}[0-9]{1,3})?' "blocklist_emule/guarding.p2p" >> "$temp_file"
        fi
    else
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?(-([0-9]{1,3}\.){3}[0-9]{1,3})?' "$file" >> "$temp_file"
    fi
}

# Function to process blocklists
process_blocklists() {
    local temp_file="$1"
    local output_dir="$2"
    local output_file="$output_dir/ipfilter.dat"
    
    echo "Starting blocklist processing..."
    
    # Create temp file
    temp_file=$(mktemp)
    echo "Created temp file: $temp_file"
    
    # Process files
    echo "Processing downloaded files..."
    local file_count=$(find . -maxdepth 1 -type f -name "blocklist_*" | wc -l)
    echo "Found $file_count files to process"
    
    local count=0
    find . -maxdepth 1 -type f -name "blocklist_*" | while read -r file; do
        count=$((count + 1))
        echo "[$count/$file_count] Processing $(basename "$file")"
        
        echo ">>> Processing $(basename "$file")..."
        process_file "$file" "$temp_file"
        echo "<<< Done with $(basename "$file")"
        
        # Show progress every 5 files
        if ((count % 5 == 0)); then
            current_count=$(wc -l < "$temp_file")
            echo "Progress: $count/$file_count files done"
            echo "Current IP count: $current_count"
        fi
    done
    
    echo "Starting deduplication..."
    local total_count=$(wc -l < "$temp_file")
    echo "Total IPs found: $total_count"
    
    # Create output directory if it doesn't exist
    mkdir -p "$output_dir"
    
    # Only sort and remove duplicates
    sort -u "$temp_file" > "$temp_file.sorted"
    mv "$temp_file.sorted" "$temp_file"
    
    local final_count=$(wc -l < "$temp_file")
    local duplicate_count=$((total_count - final_count))
    
    echo "Summary:"
    echo "- Original IP count: $total_count"
    echo "- Duplicate IPs removed: $duplicate_count"
    echo "- Final unique IPs: $final_count"
    
    # Write the final file in qBittorrent format
    write_ip_ranges "$output_file" "$temp_file"
    
    echo "Blocklists have been updated and combined into ipfilter.dat in $output_dir."
    echo "The file contains $final_count IP ranges."
    
    # Create symlink to the output file
    ln -sf "$output_file" "$(dirname "$output_dir")/ipfilter.dat"
    
    # Cleanup
    rm -f "$temp_file"
}

# Download individual blocklists
download_blocklists() {
    echo "Downloading basic blocklists..."
    
    # Level1 Blocklist - Known malicious peers and sources
    echo "1. Level1 - Known malicious peers and sources"
    download_blocklist "http://list.iblocklist.com/?list=ydxerpxkpcfqjaybcssw&fileformat=p2p&archiveformat=gz" "blocklist_level1.gz"
    
    # Pedophiles Blocklist - IPs associated with exploitation content
    echo "2. Anti-Exploitation List - Blocks IPs associated with exploitation"
    download_blocklist "http://list.iblocklist.com/?list=dufcxgnbjsdwmwctgfuj&fileformat=p2p&archiveformat=gz" "blocklist_pedo.gz"
    
    # Hijacked IPs - Compromised and hijacked IP ranges
    echo "3. Hijacked IPs - Compromised and hijacked IP ranges"
    download_blocklist "http://list.iblocklist.com/?list=usrcshglbiilevmyfhse&fileformat=p2p&archiveformat=gz" "blocklist_hijacked.gz"
    
    # Dshield Top Attackers - Most active malicious IPs
    echo "4. DShield - Top attacking IP addresses"
    download_blocklist "http://list.iblocklist.com/?list=xpbqleszmajjesnzddhv&fileformat=p2p&archiveformat=gz" "blocklist_dshield.gz"
    
    # Forumspam Blocklist - Known forum spammers
    echo "5. Forum Spam - Known forum spammers"
    download_blocklist "http://list.iblocklist.com/?list=ficutxiwawokxlcyoeye&fileformat=p2p&archiveformat=gz" "blocklist_forumspam.gz"
    
    # TOR Exit Nodes - TOR network exit points
    echo "6. TOR Exit Nodes - TOR network exit points"
    download_blocklist "http://list.iblocklist.com/?list=togdoptykrlolpddwbvz&fileformat=p2p&archiveformat=gz" "blocklist_tor.gz"
    
    # Bogon IPs - Invalid IP ranges that shouldn't be in use
    echo "7. Bogon IPs - Invalid IP ranges that shouldn’t be in use"
    download_blocklist "http://list.iblocklist.com/?list=gihxqmhyunbxhbmgqrla&fileformat=p2p&archiveformat=gz" "blocklist_bogon.gz"
    
    # Microsoft Blocklist - Microsoft identified threats
    echo "8. Microsoft - Microsoft identified threats"
    download_blocklist "http://list.iblocklist.com/?list=xshktygkujudfnjfioro&fileformat=p2p&archiveformat=gz" "blocklist_microsoft.gz"
    
    # Spider Blocklist - Aggressive web crawlers
    echo "9. Spider - Aggressive web crawlers"
    download_blocklist "http://list.iblocklist.com/?list=mcvxsnihddgutbjfbghy&fileformat=p2p&archiveformat=gz" "blocklist_spider.gz"
    
    # iBlocklist Levels - Comprehensive threat lists
    echo "10. iBlocklist Level 1 - Basic protection"
    download_blocklist "http://list.iblocklist.com/?list=bt_level1&fileformat=p2p&archiveformat=gz" "blocklist_iblock_level1.gz"
    echo "11. iBlocklist Level 2 - Intermediate protection"
    download_blocklist "http://list.iblocklist.com/?list=bt_level2&fileformat=p2p&archiveformat=gz" "blocklist_iblock_level2.gz"
    echo "12. iBlocklist Level 3 - Advanced protection"
    download_blocklist "http://list.iblocklist.com/?list=bt_level3&fileformat=p2p&archiveformat=gz" "blocklist_iblock_level3.gz"
    
    # Naunter's BT_Blocklists - Community curated list
    echo "13. Naunter - Community curated blocklist"
    download_blocklist "https://raw.githubusercontent.com/Naunter/BT_Blocklists/master/ipfilter.dat" "blocklist_naunter.dat"
    
    # eMule Security IPFilter - P2P specific threats
    echo "14. eMule - P2P specific threats"
    download_blocklist "https://upd.emule-security.org/ipfilter.zip" "blocklist_emule.zip"
    
    # BiglyBT Level1 - BitTorrent specific threats
    echo "15. BiglyBT - BitTorrent specific threats"
    download_blocklist "https://www.biglybt.com/blocklist/level1.gz" "blocklist_biglybt.gz"
    
    # FireHOL - IP lists for all threats
    echo "16. FireHOL - Comprehensive IP threat intelligence"
    download_blocklist "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" "blocklist_firehol.netset"
    
    # IPDeny Geographic Blocks
    echo "17. IPDeny US - US IP ranges"
    download_blocklist "http://www.ipdeny.com/ipblocks/data/countries/us.zone" "blocklist_ipdeny_us.zone"
    echo "18. IPDeny CN - China IP ranges"
    download_blocklist "http://www.ipdeny.com/ipblocks/data/countries/cn.zone" "blocklist_ipdeny_cn.zone"
    
    # Various Security Lists
    echo "19. MalwareDomainList - Known malware hosts"
    download_blocklist "http://www.malwaredomainlist.com/hostslist/ip.txt" "blocklist_malwaredomainlist.txt"
    echo "20. Team Cymru Bogons - Invalid IP ranges"
    download_blocklist "http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt" "blocklist_bogons.txt"
    echo "21. CINS Army - Active threat intelligence"
    download_blocklist "https://cinsscore.com/list/ci-badguys.txt" "blocklist_cins_army.txt"
    echo "22. DShield List - Attack source IPs"
    download_blocklist "https://isc.sans.edu/feeds/block.txt" "blocklist_dshield.txt"
    
    # BitTorrent Specific Lists
    echo "23. Bitsurge - BitTorrent specific threats"
    download_blocklist "https://github.com/Naunter/BT_BlockLists/raw/master/bt_blocklists.gz" "blocklist_bitsurge.gz"
    echo "24. BlocklistProject - Torrent trackers"
    download_blocklist "https://blocklistproject.github.io/Lists/torrent.txt" "blocklist_blocklistproject_torrent.txt"
    echo "25. Ultimate Blocklist - Comprehensive P2P protection"
    download_blocklist "https://github.com/walshie4/Ultimate-Blocklist/archive/main.zip" "blocklist_ultimate.zip"
    echo "26. Transmission - Transmission client blocklist"
    download_blocklist "https://github.com/ttgapers/transmission-blocklist/releases/latest/download/blocklist.gz" "blocklist_transmission.gz"
    
    # Additional Security Lists
    echo "27. BadZulo - Known bad actors"
    download_blocklist "http://list.iblocklist.com/?list=uwnukjqktoggdknzrhgh&fileformat=p2p&archiveformat=gz" "blocklist_badzulo.gz"
    echo "28. AbuseIPDB - Community reported IPs"
    download_blocklist "https://api.abuseipdb.com/api/v2/blacklist" "blocklist_abuseipdb.txt"
    echo "29. Emerging Threats - Active threats"
    download_blocklist "http://rules.emergingthreats.net/blockrules/compromised-ips.txt" "blocklist_et.txt"
    
    # Spamhaus Lists
    echo "30. Spamhaus DROP - Known spammers"
    download_blocklist "https://www.spamhaus.org/drop/drop.txt" "blocklist_spamhaus_drop.txt"
    echo "31. Spamhaus EDROP - Extended DROP list"
    download_blocklist "https://www.spamhaus.org/drop/edrop.txt" "blocklist_spamhaus_edrop.txt"
    
    # Threat Intelligence
    echo "32. Talos - Cisco Talos intelligence"
    download_blocklist "https://www.talosintelligence.com/documents/ip-blacklist" "blocklist_talos.txt"
    echo "33. AlienVault - Open threat intelligence"
    download_blocklist "https://reputation.alienvault.com/reputation.data" "blocklist_alienvault.txt"
    
    # Malware Specific
    echo "34. Feodo Tracker - Banking trojan IPs"
    download_blocklist "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" "blocklist_feodo.txt"
    echo "35. SSL Blacklist - Malicious SSL certificates"
    download_blocklist "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt" "blocklist_sslbl.txt"
    echo "36. Ransomware Tracker - Ransomware IPs"
    download_blocklist "https://ransomwaretracker.abuse.ch/downloads/RW_IPBL.txt" "blocklist_ransomware.txt"
    
    # Additional P2P Lists
    echo "37. I2P Nodes - I2P network nodes"
    download_blocklist "https://raw.githubusercontent.com/DRSDavidSoft/additional-hosts/master/domains/blacklist/i2p-nodes.txt" "blocklist_i2p.txt"
    echo "38. Abuse.ch - Malicious torrent sources"
    download_blocklist "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt" "blocklist_abuse.txt"
    echo "39. URLhaus - Malicious URLs"
    download_blocklist "https://urlhaus.abuse.ch/downloads/hostfile/" "blocklist_urlhaus.txt"
    echo "40. Dan Pollock's List - Additional threats"
    download_blocklist "https://someonewhocares.org/hosts/hosts" "blocklist_pollock.txt"
}

# Main script
echo "QBittorrent IP Filter Updater & Manager"
echo "======================================="
echo

# Check qBittorrent installation first
check_qbittorrent_installation

# Create cache directory
mkdir -p "$CACHE_DIR"

# Show initial statistics
echo
echo "Starting IP filter update process:"
echo "- Cache directory: $CACHE_DIR"
echo "- Output directory: $BLOCKLIST_DIR"
echo "- Number of blocklist sources: 40+"
echo

# Download and process blocklists
download_blocklists

# Process the downloaded lists
process_blocklists "raw_blocklist.tmp" "$BLOCKLIST_DIR"

# Show final statistics
echo
echo "IP Filter Update Complete!"
echo "=========================="
echo "- Total IP ranges processed: $total_count"
echo "- Duplicate entries removed: $duplicate_count"
echo "- Final unique IP ranges: $final_count"
echo
echo "The IP filter has been updated and is now active in qBittorrent."
echo "Location: $BLOCKLIST_DIR/ipfilter.dat"
