#!/bin/bash
# Check if all C# files are properly formatted

set -e

echo "Checking C# code formatting..."
dotnet csharpier --check .

if [ $? -eq 0 ]; then
    echo "✅ All C# files are properly formatted!"
else
    echo "❌ Some files need formatting. Run 'scripts/format.sh' to fix."
    exit 1
fi