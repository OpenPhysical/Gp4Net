#!/usr/bin/env python3
import os
import re
import sys

def find_matching_paren(text, start_pos):
    """Find the matching closing parenthesis for an opening parenthesis."""
    count = 1
    pos = start_pos + 1
    while pos < len(text) and count > 0:
        if text[pos] == '(':
            count += 1
        elif text[pos] == ')':
            count -= 1
        pos += 1
    return pos if count == 0 else -1

def extract_lambda_body(text, start_pos):
    """Extract the body of a lambda expression."""
    # Find the opening brace
    brace_pos = text.find('{', start_pos)
    if brace_pos == -1:
        return None, -1
    
    # Find matching closing brace
    count = 1
    pos = brace_pos + 1
    while pos < len(text) and count > 0:
        if text[pos] == '{':
            count += 1
        elif text[pos] == '}':
            count -= 1
        pos += 1
    
    if count == 0:
        return text[brace_pos:pos], pos
    return None, -1

def fix_matchasync_in_file(filepath):
    """Fix MatchAsync patterns in a single file."""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    
    # Pattern to find MatchAsync calls
    pattern = r'await\s+(\w+)\.MatchAsync<[^>]+>\s*\('
    
    matches = list(re.finditer(pattern, content))
    
    # Process matches in reverse order to maintain positions
    for match in reversed(matches):
        start_pos = match.start()
        var_name = match.group(1)
        
        # Find the end of the MatchAsync call
        paren_start = match.end() - 1
        end_pos = find_matching_paren(content, paren_start)
        
        if end_pos == -1:
            print(f"Warning: Could not find matching parenthesis in {filepath}")
            continue
        
        # Extract the full MatchAsync call
        full_match = content[start_pos:end_pos]
        
        # Try to extract success and error lambda bodies
        success_match = re.search(r'(\w+)\s*=>\s*{', full_match)
        if success_match:
            success_param = success_match.group(1)
            success_body_start = success_match.end() - 1
            success_body, success_end = extract_lambda_body(full_match, success_body_start - len(full_match) + start_pos)
            
            # Find error lambda
            error_match = re.search(r',\s*(\w+)\s*=>\s*{', full_match[success_end - start_pos:])
            if error_match:
                error_param = error_match.group(1)
                
                # Build replacement
                indent = re.search(r'^(\s*)', content[:start_pos].split('\n')[-1]).group(1) if '\n' in content[:start_pos] else ''
                
                replacement = f"""if ({var_name}.IsSuccess)
{indent}{{
{indent}    var {success_param} = {var_name}.Value;
{indent}    // Success case from MatchAsync
{indent}    {success_body[1:-1].strip()}
{indent}}}
{indent}else
{indent}{{
{indent}    var {error_param} = {var_name}.Error;
{indent}    // Error case from MatchAsync
{indent}    // TODO: Handle error properly
{indent}}}"""
                
                # Replace the content
                content = content[:start_pos] + replacement + content[end_pos:]
    
    if content != original_content:
        # Create backup
        backup_path = filepath + '.matchasync.bak'
        with open(backup_path, 'w', encoding='utf-8') as f:
            f.write(original_content)
        
        # Write fixed content
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"Fixed {filepath}")
        return True
    
    return False

def main():
    tool_dir = 'src/Gp4Net.Tool'
    
    if not os.path.exists(tool_dir):
        print(f"Directory {tool_dir} not found")
        sys.exit(1)
    
    fixed_count = 0
    
    for root, dirs, files in os.walk(tool_dir):
        for file in files:
            if file.endswith('.cs'):
                filepath = os.path.join(root, file)
                if fix_matchasync_in_file(filepath):
                    fixed_count += 1
    
    print(f"\nFixed {fixed_count} files")

if __name__ == '__main__':
    main()