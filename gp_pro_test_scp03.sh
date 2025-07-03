#!/bin/bash
echo "Testing SCP03 connection with GP Pro..."
echo ""

echo "1. Testing connection with factory keys:"
java -jar gp.jar -d -v --key-enc AC2AD8C8E2E874A4C6B514D7ECD5FBE5 --key-mac 86E6282CE0463C510FD4CB14D2A158EA --key-dek 7C290D97A5F4891F6C16ED7D2BB0A6E1 -l

echo ""
echo "2. Installing GP test keys:"
java -jar gp.jar -d -v --key-enc AC2AD8C8E2E874A4C6B514D7ECD5FBE5 --key-mac 86E6282CE0463C510FD4CB14D2A158EA --key-dek 7C290D97A5F4891F6C16ED7D2BB0A6E1 --lock 404142434445464748494a4b4c4d4e4f

echo ""
echo "3. Testing with GP test keys:"
java -jar gp.jar -d -v -l