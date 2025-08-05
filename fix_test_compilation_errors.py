#!/usr/bin/env python3
import os
import re

def fix_file(filepath, replacements):
    """Apply replacements to a file"""
    with open(filepath, 'r') as f:
        content = f.read()
    
    original_content = content
    
    for old, new in replacements:
        content = content.replace(old, new)
    
    if content != original_content:
        with open(filepath, 'w') as f:
            f.write(content)
        return True
    return False

def main():
    base_dir = '/Users/mistial/Projects/Gp4Net/tests/Gp4Net.Tests'
    
    # Define specific replacements for each file
    fixes = {
        # Fix async method names
        'Services/SmartCardServiceTests.cs': [
            ('SendCommandAsync(command)', 'ExecuteCommandAsync(new TestApduCommand(command))'),
            ('ConnectAsync(readerName)', 'Connect(readerName)'),
            ('DisconnectAsync()', 'Disconnect()'),
            ('_service.IsSecureChannelEstablished', '_service.Context.IsSecureChannelEstablished'),
        ],
        'Services/GlobalPlatformServiceTests.cs': [
            ('SelectAsync(aid)', 'SelectIsdAsync()'),
            ('_service.IsSecureChannelEstablished', '_service.Context.IsSecureChannelEstablished'),
            ('new GlobalPlatformService(_cardService', 'new GlobalPlatformService(_smartCardService'),
            ('ICardService _cardService', 'ISmartCardService _smartCardService'),
            ('_cardService = new TestCardService()', '_smartCardService = new TestSmartCardService()'),
            ('new CardResponse(expectedResponse)', 'new CardResponse(expectedResponse, 0x9000)'),
        ],
        # Fix constructor issues
        'Services/SmartCardServiceTests.cs': [
            ('new CommandResponse(response, 0x9000)', 'new CommandResponse(response, 0x9000, _mockContext.Object)'),
        ],
        # Fix missing types in Protocol tests
        'Protocol/Scp03ProtocolComplianceTests.cs': [
            ('new Scp03Protocol(_cryptoService, _logger)', 'new Scp03Protocol(_cryptoService, _keyDerivationService)'),
            ('ILogger<Scp03Protocol> _logger', 'IKeyDerivationService _keyDerivationService'),
            ('_logger = new NullLogger<Scp03Protocol>()', '_keyDerivationService = new Mock<IKeyDerivationService>().Object'),
            ('InitializeUpdateResponse', 'Scp03InitializeUpdateResponse'),
            ('SecurityLevel', 'Gp4Net.Domain.SecurityLevel'),
            ('SecureChannelSession', 'Gp4Net.Domain.SecureChannelSession'),
        ],
    }
    
    modified_files = []
    
    for relative_path, replacements in fixes.items():
        filepath = os.path.join(base_dir, relative_path)
        if os.path.exists(filepath):
            if fix_file(filepath, replacements):
                modified_files.append(relative_path)
    
    print(f"Modified {len(modified_files)} files:")
    for f in modified_files:
        print(f"  - {f}")

if __name__ == "__main__":
    main()