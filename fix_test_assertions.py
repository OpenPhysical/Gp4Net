#!/usr/bin/env python3
import os
import re
import sys

def fix_assertions_in_file(filepath):
    """Fix assertion methods in a single file."""
    if not os.path.exists(filepath):
        return 0

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    original_content = content
    changes = 0

    # Fix patterns
    patterns = [
        # Byte arrays and collections should use BeEquivalentTo
        (r'\.Should\(\)\.Be\(([^)]+)\)(\s*;)', r'.Should().BeEquivalentTo(\1)\2',
         lambda m: 'byte[]' in m.string[max(0, m.start()-100):m.start()] or
                   'IEnumerable<byte>' in m.string[max(0, m.start()-100):m.start()] or
                   'List<byte>' in m.string[max(0, m.start()-100):m.start()]),

        # Numeric types should use Be, not BeEquivalentTo
        (r'(\b(?:int|uint|short|ushort|long|ulong|byte|sbyte|decimal|float|double|bool)\b[^.]+)\.Should\(\)\.BeEquivalentTo\(',
         r'\1.Should().Be(', None),

        # Fix nullable numeric assertions
        (r'(\.Should\(\)\.(?:HaveValue|NotHaveValue)\(\)\.And\.)BeEquivalentTo\(', r'\1Be(', None),

        # Fix GetOrThrow() to Value
        (r'\.GetOrThrow\(\)', r'.Value', None),

        # Add Unit using directive if missing
        (r'(using System;[^}]*namespace\s+)', r'using CSharpFunctionalExtensions;\n\1',
         lambda m: 'using CSharpFunctionalExtensions;' not in m.string and 'Unit' in m.string),
    ]

    for pattern, replacement, condition in patterns:
        if condition:
            # Apply replacement only where condition is true
            for match in re.finditer(pattern, content):
                if condition(match):
                    content = content[:match.start()] + re.sub(pattern, replacement, match.group()) + content[match.end():]
                    changes += 1
        else:
            # Apply replacement globally
            new_content = re.sub(pattern, replacement, content)
            if new_content != content:
                changes += len(re.findall(pattern, content))
                content = new_content

    # Special handling for specific numeric assertion patterns
    # Fix cases like: result.Value.Length.Should().Be(16);
    content = re.sub(
        r'(\.(?:Length|Count|Size|Index|Position|Offset|Version|Level|Status|Id|Key|Value|Major|Minor|Patch|Build|Revision|Year|Month|Day|Hour|Minute|Second|Millisecond|Ticks|TotalSeconds|TotalMilliseconds|TotalMinutes|TotalHours|TotalDays)\.Should\(\))\.BeEquivalentTo\(',
        r'\1.Be(',
        content
    )

    # Fix bool assertions
    content = re.sub(
        r'(\.Should\(\))\.BeEquivalentTo\((true|false)\)',
        r'\1.Be(\2)',
        content
    )

    # Fix enum assertions
    content = re.sub(
        r'(\.Should\(\))\.BeEquivalentTo\((\w+\.\w+)\)',
        lambda m: m.group(1) + '.Be(' + m.group(2) + ')' if any(enum in m.group(2) for enum in ['SecurityLevel.', 'CardLifeCycle.', 'Protocol.', 'KeyType.', 'Algorithm.']) else m.group(0),
        content
    )

    if content != original_content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return changes

    return 0

def main():
    test_dir = 'tests/Gp4Net.Tests'
    total_changes = 0

    for root, dirs, files in os.walk(test_dir):
        for file in files:
            if file.endswith('.cs'):
                filepath = os.path.join(root, file)
                changes = fix_assertions_in_file(filepath)
                if changes > 0:
                    print(f"Fixed {changes} issues in {filepath}")
                    total_changes += changes

    print(f"\nTotal changes made: {total_changes}")

if __name__ == '__main__':
    main()
