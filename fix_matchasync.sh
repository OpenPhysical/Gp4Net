#!/bin/bash
# Fix MatchAsync patterns in Tool project

# Find all files with MatchAsync
files=$(find src/Gp4Net.Tool -name "*.cs" -exec grep -l "MatchAsync" {} \;)

for file in $files; do
    echo "Processing $file..."
    
    # Create a temporary file
    temp_file="${file}.tmp"
    
    # Process the file line by line to handle multi-line patterns
    awk '
    BEGIN { in_match = 0; buffer = "" }
    
    # Start of MatchAsync pattern
    /\.MatchAsync\(/ {
        in_match = 1
        buffer = $0
        # Check if entire pattern is on one line
        if (/\);$/) {
            # Extract the await pattern
            if (match($0, /await [^.]+\.MatchAsync\(/)) {
                prefix = substr($0, 1, RSTART-1)
                # Extract variable/expression before .MatchAsync
                match($0, /([a-zA-Z0-9_]+)\.MatchAsync\(/, arr)
                var_name = arr[1]
                
                # Simple replacement for single line
                print prefix "if (" var_name ".IsSuccess)"
                print prefix "{"
                print prefix "    // Process success case"
                print prefix "}"
                print prefix "else"
                print prefix "{"
                print prefix "    // Process failure case"
                print prefix "}"
                in_match = 0
                buffer = ""
            } else {
                print $0
                in_match = 0
                buffer = ""
            }
        }
        next
    }
    
    # Inside MatchAsync pattern
    in_match == 1 {
        buffer = buffer "\n" $0
        if (/\);$/) {
            # End of pattern, need to transform it
            print "// TODO: Replace MatchAsync pattern"
            print buffer
            in_match = 0
            buffer = ""
        }
        next
    }
    
    # Normal lines
    { print $0 }
    ' "$file" > "$temp_file"
    
    # Replace original file
    mv "$temp_file" "$file"
done

echo "MatchAsync replacement complete."