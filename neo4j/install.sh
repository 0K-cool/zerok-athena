#!/usr/bin/env bash
# neo4j/install.sh — Install Neo4j Community 5.x on Kali (Debian-based)
set -euo pipefail

echo "[*] Adding Neo4j repository..."
wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/neo4j.gpg
echo 'deb [signed-by=/usr/share/keyrings/neo4j.gpg] https://debian.neo4j.com stable latest' | \
  sudo tee /etc/apt/sources.list.d/neo4j.list

echo "[*] Installing Neo4j..."
sudo apt-get update
sudo apt-get install -y neo4j

echo "[*] Configuring Neo4j for LAN access..."
sudo sed -i 's/#server.default_listen_address=0.0.0.0/server.default_listen_address=0.0.0.0/' /etc/neo4j/neo4j.conf

echo "[*] Setting initial password..."
sudo neo4j-admin dbms set-initial-password athena2026

echo "[*] Starting Neo4j..."
sudo systemctl enable neo4j
sudo systemctl start neo4j

echo "[+] Neo4j installed. Bolt: bolt://172.26.80.76:7687  Browser: http://172.26.80.76:7474"
