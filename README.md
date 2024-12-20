# This script is designed to update and format blocklists for use in qBittorrent.
# It downloads multiple blocklists from various sources, processes them into a compatible format,
# and combines them into a single `ipfilter.dat` file that qBittorrent can use to block specific IP ranges.
# Supported formats include .gz, .zip, .dat, and .txt files. The script also handles CIDR notation
# and converts it into IP ranges compatible with qBittorrent.

# Function to search for qBittorrent directory if not found in default location
