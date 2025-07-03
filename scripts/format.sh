#!/bin/bash
# Format all C# files using CSharpier

set -e

echo "Formatting C# files with CSharpier..."
dotnet csharpier .

echo "✅ All C# files have been formatted!"