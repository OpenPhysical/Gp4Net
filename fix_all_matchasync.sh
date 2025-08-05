#!/bin/bash

# Fix all MatchAsync patterns in Tool project
cd /Users/mistial/Projects/Gp4Net

# Fix MatchAsync patterns
echo "Fixing MatchAsync patterns..."
find src/Gp4Net.Tool -name "*.cs" -exec grep -l "MatchAsync" {} \; | while read file; do
    echo "Processing $file..."
    
    # Create backup
    cp "$file" "$file.bak"
    
    # Replace MatchAsync patterns with if/else
    perl -i -pe 's/await\s+(\w+)\.MatchAsync<[^>]+>\(/if ($1.IsSuccess)\n{\n    var value = $1.Value;\n    \/\/ TODO: Replace success case\n}\nelse\n{\n    var error = $1.Error;\n    \/\/ TODO: Replace error case\n}\n\/\/ Original MatchAsync: /g' "$file"
done

echo "Done fixing MatchAsync patterns"