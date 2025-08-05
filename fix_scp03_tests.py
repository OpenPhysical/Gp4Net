#!/usr/bin/env python3
import re

# Read the file
with open('/Users/mistial/Projects/Gp4Net/tests/Gp4Net.Tests/Domain/Protocol/Scp03ProtocolTests.cs', 'r') as f:
    content = f.read()

# Fix patterns
# Pattern 1: new Scp03Protocol(keySet)
content = re.sub(r'new Scp03Protocol\(keySet\)', 
                'new Scp03Protocol(keySet, _keyDerivationServiceMock.Object)', 
                content)

# Pattern 2: new Scp03Protocol(keySet, implementation) where implementation is a number
content = re.sub(r'new Scp03Protocol\(keySet, (0x[0-9A-Fa-f]+)\)', 
                r'new Scp03Protocol(keySet, _keyDerivationServiceMock.Object, \1)', 
                content)

# Pattern 3: new Scp03Protocol(keySet, implementation) where implementation is a variable
content = re.sub(r'new Scp03Protocol\(keySet, implementation\)', 
                'new Scp03Protocol(keySet, _keyDerivationServiceMock.Object, implementation)', 
                content)

# Pattern 4: new Scp03Protocol(null!)
content = re.sub(r'new Scp03Protocol\(null!\)', 
                'new Scp03Protocol(null!, _keyDerivationServiceMock.Object)', 
                content)

# Write the file back
with open('/Users/mistial/Projects/Gp4Net/tests/Gp4Net.Tests/Domain/Protocol/Scp03ProtocolTests.cs', 'w') as f:
    f.write(content)

print("Fixed all Scp03Protocol constructor calls")