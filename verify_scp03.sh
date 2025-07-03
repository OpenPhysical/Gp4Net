#!/bin/bash
echo "Verifying SCP03 configuration with GP Pro..."
echo ""

echo "1. Getting card info (should show SCP03 support):"
java -jar gp.jar -d -v --key-enc AC2AD8C8E2E874A4C6B514D7ECD5FBE5 --key-mac 86E6282CE0463C510FD4CB14D2A158EA --key-dek 7C290D97A5F4891F6C16ED7D2BB0A6E1 -i

echo ""
echo "2. Trying to connect with SCP03:"
java -jar gp.jar -d -v --key-enc AC2AD8C8E2E874A4C6B514D7ECD5FBE5 --key-mac 86E6282CE0463C510FD4CB14D2A158EA --key-dek 7C290D97A5F4891F6C16ED7D2BB0A6E1 --scp 3 -l