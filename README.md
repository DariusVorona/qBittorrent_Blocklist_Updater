 QBittorrent IP Filter Manager
 Version: 2.1
 License: GPL-2.0

 DESCRIPTION:
 
 This script manages IP filters for qBittorrent by downloading and processing
 multiple blocklists from trusted sources. It combines these lists into a single
 ipfilter.dat file that qBittorrent uses to block potentially harmful peers.

# FEATURES:
 
 1. Installation Detection:
    - Automatically detects qBittorrent installation (APT, RPM, Flatpak)
    - Checks for and offers to install updates
    - Finds correct configuration directory

 2. Blocklist Management:
    - Downloads 40+ specialized blocklists
    - Handles various file formats (gz, zip, dat, txt)
    - Converts CIDR notation to IP ranges
    - Removes duplicate entries
    - Caches downloads to prevent unnecessary updates

 3. Protection Types:
    - Malicious peers and botnets
    - Known bad actors
    - TOR exit nodes
    - Spam sources
    - Geographic IP ranges
    - Malware distributors
    - Compromised IPs

 4. Progress Reporting:
    - Shows download progress
    - Displays processing statistics
    - Reports final IP counts
    - Shows duplicate removal stats
