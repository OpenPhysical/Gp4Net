#!/usr/bin/env python3
"""
Unified trace converter for GP Pro and GPShell traces.
Extracts all available data and generates rich JSON with comprehensive metadata.

Usage:
    python convert_trace.py input_trace.log output.json
    python convert_trace.py docs/traces/*.log --batch
"""

import sys
import json
import re
import argparse
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class Exchange:
    """Single APDU exchange with extracted metadata."""
    command: str
    response: str
    description: str
    response_time_ms: Optional[int] = None
    source_line: Optional[int] = None
    secure_messaging: Optional[bool] = None


@dataclass
class SessionData:
    """SCP session metadata extracted from logs."""
    scp_version: int
    implementation: str
    key_version: int
    host_challenge: str
    card_challenge: str
    sequence_counter: str
    key_diversification_data: str
    card_cryptogram: str
    host_cryptogram: str
    static_keys: Optional[str] = None
    session_keys: Optional[Dict[str, str]] = None


@dataclass
class CardInfo:
    """Card information extracted from traces."""
    atr: str
    isd_aid: str
    card_type: Optional[str] = None


@dataclass
class TraceMetadata:
    """Comprehensive trace metadata."""
    source_file: str
    format_type: str
    generated: str
    tool_version: str
    card: CardInfo
    sessions: List[SessionData]
    warnings: List[str]


class TraceLineParser:
    """Unified parser for GP Pro and GPShell trace formats."""
    
    def __init__(self):
        # GP Pro patterns
        self.gp_pro_command_pattern = re.compile(r'^A>> T=\d+ \([\d+]+\) ([0-9A-F\s]+)$')
        self.gp_pro_response_pattern = re.compile(r'^A<< \([\d+]+\) \((\d+)ms\) ([0-9A-F\s]+)$')
        
        # GPShell patterns
        self.gpshell_send_pattern = re.compile(r'Command --> ([0-9A-F\s]+)')
        self.gpshell_recv_pattern = re.compile(r'Response <-- ([0-9A-F\s]+)')
        
        # Session data extraction patterns (case-insensitive where appropriate)
        self.static_keys_pattern = re.compile(r'no keys given, defaulting to ([0-9A-Fa-f]+)', re.IGNORECASE)
        self.session_keys_pattern = re.compile(r'Session keys: ENC=([0-9A-Fa-f]+) MAC=([0-9A-Fa-f]+) RMAC=([0-9A-Fa-f]+)', re.IGNORECASE)
        self.host_challenge_pattern = re.compile(r'(?:Generated host challenge|Host challenge): ([0-9A-Fa-f]+)', re.IGNORECASE)
        self.card_challenge_pattern = re.compile(r'Card challenge: ([0-9A-Fa-f]+)', re.IGNORECASE)
        self.card_cryptogram_pattern = re.compile(r'Verified card cryptogram: ([0-9A-Fa-f]+)', re.IGNORECASE)
        self.host_cryptogram_pattern = re.compile(r'Calculated host cryptogram: ([0-9A-Fa-f]+)', re.IGNORECASE)
        self.kdd_pattern = re.compile(r'KDD: ([0-9A-Fa-f]+)', re.IGNORECASE)
        self.ssc_pattern = re.compile(r'SSC: ([0-9A-Fa-f]+)', re.IGNORECASE)
        self.scp_version_pattern = re.compile(r'Card reports SCP0([23]) with key version (\d+)', re.IGNORECASE)
        self.mode_pattern = re.compile(r'--mode (MAC|ENC|CLR)', re.IGNORECASE)
        self.session_setup_pattern = re.compile(r'setting up session with (.+)', re.IGNORECASE)
        self.diversified_keys_pattern = re.compile(r'Diversified card keys: ENC=([0-9A-Fa-f]+).*MAC=([0-9A-Fa-f]+).*DEK=([0-9A-Fa-f]+)', re.IGNORECASE)
        
    def detect_format(self, content: str) -> str:
        """Detect trace format from content."""
        if 'GlobalPlatformPro' in content or 'A>>' in content:
            return 'gp_pro'
        elif 'Command -->' in content or 'gpshell' in content.lower():
            return 'gpshell'
        else:
            return 'unknown'
    
    def parse_file(self, filename: str) -> Tuple[List[Exchange], List[SessionData], List[str]]:
        """Parse trace file and extract all available data."""
        with open(filename, 'r') as f:
            lines = f.readlines()
        
        content = ''.join(lines)
        format_type = self.detect_format(content)
        
        if format_type == 'gp_pro':
            return self._parse_gp_pro(lines)
        elif format_type == 'gpshell':
            return self._parse_gpshell(lines)
        else:
            raise ValueError(f"Unknown trace format in {filename}")
    
    def _parse_gp_pro(self, lines: List[str]) -> Tuple[List[Exchange], List[SessionData], List[str]]:
        """Parse GP Pro format trace."""
        exchanges = []
        sessions = []
        warnings = []
        current_command = None
        current_line = None
        session_data = {}
        
        # Track session boundaries - collect all exchanges first, then partition by sessions
        exchange_boundary_markers = []  # Track potential session boundaries
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Extract session data from all lines (including comments)
            self._extract_session_data(line, session_data)
            
            # Skip empty lines and some debug lines for APDU parsing
            if not line or line.startswith('#') or line.startswith('[TRACE]'):
                continue
            
            # Try to match command
            cmd_match = self.gp_pro_command_pattern.match(line)
            if cmd_match:
                current_command = cmd_match.group(1).strip().replace(' ', '').upper()
                current_line = line_num
                continue
            
            # Try to match response
            resp_match = self.gp_pro_response_pattern.match(line)
            if resp_match and current_command:
                response_time = int(resp_match.group(1))
                response_data = resp_match.group(2).strip().replace(' ', '').upper()
                
                # Create exchange with rich description
                description = self._describe_command(current_command, response_data)
                secure_messaging = self._is_secure_messaging(current_command)
                
                exchange = Exchange(
                    command=current_command,
                    response=response_data,
                    description=description,
                    response_time_ms=response_time,
                    source_line=current_line,
                    secure_messaging=secure_messaging
                )
                
                # Mark potential session boundaries: SELECT followed by INITIALIZE UPDATE
                if current_command.startswith('00A404'):  # SELECT
                    exchange_boundary_markers.append(('SELECT', len(exchanges)))
                elif current_command.startswith('8050'):  # INITIALIZE UPDATE
                    exchange_boundary_markers.append(('INIT_UPDATE', len(exchanges)))
                
                exchanges.append(exchange)
                current_command = None
                current_line = None
        
        # Detect actual session boundaries and create session data for each
        session_boundaries = self._detect_session_boundaries(exchange_boundary_markers, exchanges)
        
        if len(session_boundaries) > 1:
            # Create specific session data for each detected session by extracting from exchanges
            for i, (start_idx, end_idx) in enumerate(session_boundaries):
                session_exchanges = exchanges[start_idx:end_idx]
                # Extract session-specific data from the exchanges themselves
                session_specific_data = self._extract_session_data_from_exchanges(session_exchanges)
                if session_specific_data:
                    sessions.append(self._build_session_data(session_specific_data, session_exchanges))
                else:
                    # Fallback to global session data
                    sessions.append(self._build_session_data(session_data, session_exchanges))
        else:
            # Single session - use original logic
            if session_data:
                sessions.append(self._build_session_data(session_data, exchanges))
        
        return exchanges, sessions, warnings
    
    def _detect_session_boundaries(self, boundary_markers: List[tuple], exchanges: List[Exchange]) -> List[tuple]:
        """Detect session boundaries based on SELECT + INITIALIZE UPDATE patterns."""
        boundaries = []
        current_start = 0
        
        # Look for SELECT followed by INITIALIZE UPDATE patterns
        i = 0
        while i < len(boundary_markers):
            marker_type, exchange_idx = boundary_markers[i]
            
            if marker_type == 'SELECT':
                # Look for following INITIALIZE UPDATE
                if i + 1 < len(boundary_markers):
                    next_marker_type, next_exchange_idx = boundary_markers[i + 1]
                    if next_marker_type == 'INIT_UPDATE':
                        # Found session boundary at SELECT position
                        if current_start < exchange_idx:
                            boundaries.append((current_start, exchange_idx))
                        current_start = exchange_idx
                        i += 2  # Skip both SELECT and INIT_UPDATE
                        continue
            
            i += 1
        
        # Add final boundary
        if current_start < len(exchanges):
            boundaries.append((current_start, len(exchanges)))
        
        # If we only found one boundary, return single session
        if len(boundaries) <= 1:
            return [(0, len(exchanges))]
        
        return boundaries
    
    def _extract_session_data_from_exchanges(self, session_exchanges: List[Exchange]) -> Dict[str, Any]:
        """Extract session data directly from INITIALIZE UPDATE exchanges in the session."""
        session_data = {}
        
        # Find INITIALIZE UPDATE exchange in this session
        init_update_exchange = None
        for exchange in session_exchanges:
            if exchange.command.startswith('8050'):
                init_update_exchange = exchange
                break
        
        if not init_update_exchange:
            return {}
        
        try:
            # Extract host challenge from command (8 bytes after header)
            command = init_update_exchange.command
            if len(command) >= 18:  # 8050000008 + 16 hex chars (8 bytes)
                host_challenge = command[10:26]  # Skip "8050000008"
                session_data['host_challenge'] = host_challenge
            
            # Extract response data
            response = init_update_exchange.response
            if response.endswith('9000'):
                response_data = response[:-4]  # Remove SW
                
                # Parse INITIALIZE UPDATE response based on SCP version
                parsed_data = self._parse_initialize_update_response(response_data)
                session_data.update(parsed_data)
                
                # Use existing logic to determine SCP version
                session_data['scp_version'] = parsed_data.get('scp_version', 3)
                
        except Exception as e:
            print(f"Warning: Failed to extract session data from exchanges: {e}")
            return {}
        
        return session_data
    
    def _parse_gpshell(self, lines: List[str]) -> Tuple[List[Exchange], List[SessionData], List[str]]:
        """Parse GPShell format trace."""
        exchanges = []
        sessions = []
        warnings = []
        current_command = None
        current_line = None
        session_data = {}
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            
            # Extract session data from debug logs
            self._extract_session_data(line, session_data)
            
            # Try to match command
            send_match = self.gpshell_send_pattern.search(line)
            if send_match:
                current_command = send_match.group(1).strip().replace(' ', '').upper()
                current_line = line_num
                continue
            
            # Try to match response
            recv_match = self.gpshell_recv_pattern.search(line)
            if recv_match and current_command:
                response_data = recv_match.group(1).strip().replace(' ', '').upper()
                
                description = self._describe_command(current_command, response_data)
                secure_messaging = self._is_secure_messaging(current_command)
                
                exchange = Exchange(
                    command=current_command,
                    response=response_data,
                    description=description,
                    response_time_ms=None,  # GPShell doesn't provide timing
                    source_line=current_line,
                    secure_messaging=secure_messaging
                )
                
                exchanges.append(exchange)
                current_command = None
                current_line = None
        
        # Build session data if we found any
        if session_data:
            sessions.append(self._build_session_data(session_data, exchanges))
        
        return exchanges, sessions, warnings
    
    def _extract_session_data(self, line: str, session_data: Dict[str, Any]) -> None:
        """Extract session-related data from log lines."""
        # Static keys
        if match := self.static_keys_pattern.search(line):
            session_data['static_keys'] = match.group(1)
        
        # Session keys
        if match := self.session_keys_pattern.search(line):
            session_data['session_keys'] = {
                's_enc': match.group(1),
                's_mac': match.group(2),
                's_rmac': match.group(3)
            }
        
        # Diversified (static) keys
        if match := self.diversified_keys_pattern.search(line):
            if 'diversified_keys' not in session_data:
                session_data['diversified_keys'] = {
                    'enc': match.group(1),
                    'mac': match.group(2), 
                    'dek': match.group(3)
                }
        
        # Host challenge
        if match := self.host_challenge_pattern.search(line):
            session_data['host_challenge'] = match.group(1)
        
        # Card challenge (extract 6 bytes from the full challenge)
        if match := self.card_challenge_pattern.search(line):
            full_challenge = match.group(1)
            # Card challenge is typically 6 bytes (12 hex chars) after sequence counter
            if len(full_challenge) >= 16:  # sequence counter (2 bytes) + card challenge (6 bytes)
                session_data['sequence_counter'] = full_challenge[:4]
                session_data['card_challenge'] = full_challenge[4:16]
            else:
                session_data['card_challenge'] = full_challenge
        
        # Card cryptogram
        if match := self.card_cryptogram_pattern.search(line):
            session_data['card_cryptogram'] = match.group(1)
        
        # Host cryptogram
        if match := self.host_cryptogram_pattern.search(line):
            session_data['host_cryptogram'] = match.group(1)
        
        # KDD
        if match := self.kdd_pattern.search(line):
            session_data['kdd'] = match.group(1)
        
        # SSC (if not already extracted from card challenge)
        if match := self.ssc_pattern.search(line):
            if 'sequence_counter' not in session_data:
                session_data['sequence_counter'] = match.group(1).zfill(4)
        
        # SCP version and key version
        if match := self.scp_version_pattern.search(line):
            session_data['scp_version'] = int(match.group(1))
            session_data['key_version'] = int(match.group(2))
        
        # Mode detection (CLR, MAC, ENC)
        if match := self.mode_pattern.search(line):
            session_data['mode'] = match.group(1)
        
        # Session setup info
        if match := self.session_setup_pattern.search(line):
            session_data['security_level'] = match.group(1).strip()
    
    def _build_session_data(self, session_data: Dict[str, Any], exchanges: List[Exchange]) -> SessionData:
        """Build SessionData from extracted data and trace analysis."""
        # Parse actual SCP version from INITIALIZE UPDATE response
        actual_scp_info = self._parse_initialize_update_from_exchanges(exchanges)
        scp_version = actual_scp_info.get('scp_version') or session_data.get('scp_version', 2)
        
        # Determine implementation from actual security behavior analysis
        implementation = 'i=00'  # Default
        
        if scp_version == 2:
            # For SCP02, analyze the actual security patterns in the trace
            implementation = self._determine_scp02_implementation(session_data, exchanges)
        elif scp_version == 3:
            # For SCP03, extract implementation from response
            implementation = actual_scp_info.get('implementation', 'i=70')
        
        # Use parsed card challenge if available
        card_challenge = actual_scp_info.get('card_challenge') or session_data.get('card_challenge', '')
        sequence_counter = actual_scp_info.get('sequence_counter') or session_data.get('sequence_counter', '')
        key_diversification_data = actual_scp_info.get('key_diversification_data') or session_data.get('kdd', '')
        card_cryptogram = actual_scp_info.get('card_cryptogram') or session_data.get('card_cryptogram', '')
        
        # Use session-specific host challenge if available
        host_challenge = session_data.get('host_challenge', '')
        host_cryptogram = session_data.get('host_cryptogram', '')
        
        return SessionData(
            scp_version=scp_version,
            implementation=implementation,
            key_version=session_data.get('key_version', 1),
            host_challenge=host_challenge,
            card_challenge=card_challenge,
            sequence_counter=sequence_counter,
            key_diversification_data=key_diversification_data,
            card_cryptogram=card_cryptogram,
            host_cryptogram=host_cryptogram,
            static_keys=session_data.get('static_keys'),
            session_keys=session_data.get('session_keys')
        )
    
    def _parse_initialize_update_from_exchanges(self, exchanges: List[Exchange]) -> Dict[str, Any]:
        """Parse INITIALIZE UPDATE response to extract actual SCP protocol information."""
        for exchange in exchanges:
            if "INITIALIZE UPDATE" in exchange.description:
                return self._parse_initialize_update_response(exchange.response)
        return {}
    
    def _parse_initialize_update_response(self, response_hex: str) -> Dict[str, Any]:
        """Parse INITIALIZE UPDATE response to extract actual SCP protocol info.
        
        Response format: [KEY_DIVERSIFICATION_DATA][CARD_CHALLENGE][CARD_CRYPTOGRAM][SW1][SW2]
        Where the first byte of KEY_DIVERSIFICATION_DATA contains the SCP ID.
        """
        if len(response_hex) < 10 or not response_hex.endswith('9000'):
            return {}
        
        # Remove status word (last 4 chars)
        response_data = response_hex[:-4]
        if len(response_data) < 56:  # Minimum for SCP02 (28 bytes = 56 hex chars)
            return {}
        
        try:
            # Parse INITIALIZE UPDATE response structure:
            # KDD (10 bytes) + Key Version (1 byte) + SCP ID (1 byte) + Implementation (1 byte) + [SCP-specific data]
            result = {}
            
            # Extract key diversification data (first 10 bytes)
            result['key_diversification_data'] = response_data[:20]  # 10 bytes (20 hex chars)
            
            # Extract key version (1 byte after KDD)
            key_version_byte = int(response_data[20:22], 16)
            
            # Extract SCP ID (1 byte after key version)
            scp_id = int(response_data[22:24], 16)
            
            # Extract implementation parameter (1 byte after SCP ID)
            implementation_param = int(response_data[24:26], 16)
            
            if scp_id == 0x02:  # SCP02
                # SCP02: KDD(10) + KeyVer(1) + SCP(1) + Impl(1) + SeqCounter(2) + CardChall(6) + CardCrypto(8)
                if len(response_data) >= 56:  # 28 bytes minimum
                    result['scp_version'] = 2
                    result['sequence_counter'] = response_data[26:30]  # 2 bytes after impl param
                    result['card_challenge'] = response_data[30:42]  # 6 bytes
                    result['card_cryptogram'] = response_data[42:58]  # 8 bytes
                    result['implementation'] = f'i={implementation_param:02X}'
                    
            elif scp_id == 0x03:  # SCP03
                # SCP03: KDD(10) + KeyVer(1) + SCP(1) + Impl(1) + CardChall(8) + CardCrypto(8) + SeqCounter(3)
                if len(response_data) >= 58:  # 29 bytes minimum
                    result['scp_version'] = 3
                    result['card_challenge'] = response_data[26:42]  # 8 bytes after impl param
                    result['card_cryptogram'] = response_data[42:58]  # 8 bytes
                    result['implementation'] = f'i={implementation_param:02X}'
                    
            return result
            
        except (ValueError, IndexError):
            return {}
    
    
    def _determine_scp02_implementation(self, session_data: Dict[str, Any], exchanges: List[Exchange]) -> str:
        """Determine SCP02 implementation from security behavior patterns."""
        # Look for GP Pro mode hints first
        mode = session_data.get('mode', '')
        security_level = session_data.get('security_level', '')
        
        # Analyze EXTERNAL AUTHENTICATE command for security level
        external_auth_found = False
        uses_encryption = False
        uses_secure_messaging = False
        
        for exchange in exchanges:
            if "EXTERNAL AUTHENTICATE" in exchange.description:
                # Check P1 parameter in EXTERNAL AUTHENTICATE for security level
                if len(exchange.command) >= 8:
                    p1 = int(exchange.command[4:6], 16)  # P1 is at offset 2 (bytes 4-5 in hex string)
                    if p1 == 0x00:  # CLR - no secure messaging
                        return 'i=15'  # Most common SCP02 CLR implementation
                    elif p1 == 0x01:  # MAC only
                        return 'i=35'  # SCP02 with R-MAC support  
                    elif p1 == 0x03:  # MAC + ENC
                        return 'i=55'  # SCP02 with well-known challenge (ENC mode)
                external_auth_found = True
            elif exchange.command.startswith('84'):  # Secure messaging
                uses_secure_messaging = True
                # Check if command data is encrypted (longer than expected for MAC-only)
                if len(exchange.command) >= 16:  # Minimum for encrypted command
                    # If data length suggests encryption (e.g., 16 bytes vs 10 bytes for MAC-only)
                    expected_mac_only_length = 10
                    actual_data_length = len(exchange.command[8:-2]) // 2  # Data field length in bytes
                    if actual_data_length > expected_mac_only_length:
                        uses_encryption = True
        
        # Fallback analysis based on GP Pro mode strings
        if 'CLR' in mode.upper() or 'CLR' in security_level.upper():
            return 'i=15'  # CLR mode
        elif 'MAC, ENC' in security_level or 'ENC' in mode.upper():
            return 'i=55'  # ENC mode with encryption
        elif 'MAC' in mode.upper() or 'MAC' in security_level:
            return 'i=35'  # MAC mode
        
        # Final fallback based on secure messaging analysis
        if not uses_secure_messaging:
            return 'i=15'  # CLR mode - no secure messaging
        elif uses_encryption:
            return 'i=55'  # ENC mode - encryption detected
        else:
            return 'i=35'  # MAC mode - secure messaging without encryption
    
    def _describe_command(self, command: str, response: str) -> str:
        """Generate human-readable description of APDU command."""
        if len(command) < 4:
            return "UNKNOWN"
        
        ins = command[2:4].upper()
        
        # Basic command descriptions
        descriptions = {
            'A4': 'SELECT',
            '50': 'INITIALIZE UPDATE',
            '82': 'EXTERNAL AUTHENTICATE',
            'F2': 'GET STATUS',
            'CA': 'GET DATA',
            'E6': 'INSTALL',
            'E8': 'LOAD',
            'E4': 'DELETE'
        }
        
        base_desc = descriptions.get(ins, f'UNKNOWN (INS={ins})')
        
        # Add more specific context
        if ins == 'A4':
            return 'SELECT ISD'
        elif ins == '50':
            # Parse actual SCP version from response
            parsed_info = self._parse_initialize_update_response(response)
            if parsed_info.get('scp_version') == 2:
                return 'INITIALIZE UPDATE - SCP02'
            elif parsed_info.get('scp_version') == 3:
                return 'INITIALIZE UPDATE - SCP03'
            return base_desc
        elif ins == '82':
            if command.startswith('84'):
                return 'EXTERNAL AUTHENTICATE - Secure messaging'
            return base_desc
        elif ins == 'F2':
            if command.startswith('84'):
                return 'GET STATUS - Secure messaging'
            return base_desc
        
        return base_desc
    
    def _is_secure_messaging(self, command: str) -> bool:
        """Check if command uses secure messaging."""
        if len(command) < 2:
            return False
        cla = int(command[:2], 16)
        return (cla & 0x04) != 0


class TraceConverter:
    """Main converter that orchestrates parsing and output generation."""
    
    def __init__(self):
        self.parser = TraceLineParser()
        self.tool_version = "gp4net-unified-converter-1.0"
    
    def convert_file(self, input_file: str, output_file: str) -> Dict[str, Any]:
        """Convert a single trace file to rich JSON format."""
        print(f"Converting: {input_file}")
        
        # Parse the trace
        exchanges, sessions, warnings = self.parser.parse_file(input_file)
        
        # Always use single file conversion - keep all exchanges together with multi-session support
        return self._convert_single_session_file(input_file, output_file, exchanges, sessions, warnings)

    def _convert_single_session_file(self, input_file: str, output_file: str, 
                                   exchanges: List[Exchange], sessions: List[SessionData], 
                                   warnings: List[str]) -> Dict[str, Any]:
        """Convert a single-session trace file."""
        # Extract card info from exchanges
        card_info = self._extract_card_info(exchanges)
        
        # Build comprehensive metadata
        metadata = TraceMetadata(
            source_file=input_file,
            format_type=self.parser.detect_format(open(input_file).read()),
            generated=datetime.utcnow().isoformat() + 'Z',
            tool_version=self.tool_version,
            card=card_info,
            sessions=sessions,
            warnings=warnings
        )
        
        # Generate test hints if we have testable operations
        test_hints = self._generate_test_hints(exchanges, sessions)
        
        # Build final JSON structure
        result = {
            "metadata": self._metadata_to_dict(metadata),
            "test_hints": test_hints,
            "exchanges": [self._exchange_to_dict(ex) for ex in exchanges],
            "sessions": {f"session_{i+1}": self._session_to_dict(session) 
                        for i, session in enumerate(sessions)}
        }
        
        # Add hints section for test compatibility
        if sessions and sessions[0].static_keys:
            result["metadata"]["hints"] = {
                "static_keys": sessions[0].static_keys,
                "expected_session_keys": sessions[0].session_keys or {}
            }
        
        # Write output
        with open(output_file, 'w') as f:
            json.dump(result, f, indent=2)
        
        print(f"Generated: {output_file}")
        print(f"  Exchanges: {len(exchanges)}")
        print(f"  Sessions: {len(sessions)}")
        if sessions:
            session = sessions[0]
            print(f"  SCP{session.scp_version} {session.implementation}")
            if session.session_keys:
                print(f"  Session keys: ✓")
        
        return result
    
    def _convert_multi_session_file(self, input_file: str, output_file: str,
                                  exchanges: List[Exchange], sessions: List[SessionData],
                                  warnings: List[str]) -> Dict[str, Any]:
        """Convert a multi-session trace file into separate files."""
        print(f"Detected {len(sessions)} sessions, splitting into separate files...")
        
        # Extract base filename for session files
        base_path = output_file.rsplit('.', 1)[0]
        extension = output_file.rsplit('.', 1)[1] if '.' in output_file else 'json'
        
        # Track session boundaries in exchanges
        session_exchanges = self._partition_exchanges_by_session(exchanges, sessions)
        
        results = []
        for i, (session, session_exch) in enumerate(zip(sessions, session_exchanges)):
            # Create session-specific filename
            session_file = f"{base_path}_session{i+1}.{extension}"
            
            # Extract card info from session exchanges
            card_info = self._extract_card_info(session_exch)
            
            # Build metadata for this session
            metadata = TraceMetadata(
                source_file=input_file,
                format_type=self.parser.detect_format(open(input_file).read()),
                generated=datetime.utcnow().isoformat() + 'Z',
                tool_version=f"{self.tool_version}-session-split",
                card=card_info,
                sessions=[session],
                warnings=warnings
            )
            
            # Generate test hints for this session
            test_hints = self._generate_test_hints(session_exch, [session])
            
            # Build JSON structure for this session
            result = {
                "metadata": self._metadata_to_dict(metadata),
                "test_hints": test_hints,
                "exchanges": [self._exchange_to_dict(ex) for ex in session_exch],
                "sessions": {"session_1": self._session_to_dict(session)}
            }
            
            # Add hints section for test compatibility
            if session.static_keys:
                result["metadata"]["hints"] = {
                    "static_keys": session.static_keys,
                    "expected_session_keys": session.session_keys or {}
                }
            
            # Write session file
            with open(session_file, 'w') as f:
                json.dump(result, f, indent=2)
            
            print(f"Generated session {i+1}: {session_file}")
            print(f"  Exchanges: {len(session_exch)}")
            print(f"  SCP{session.scp_version} {session.implementation}")
            results.append(result)
        
        return results[0] if results else {}
    
    def _partition_exchanges_by_session(self, exchanges: List[Exchange], 
                                      sessions: List[SessionData]) -> List[List[Exchange]]:
        """Partition exchanges by their corresponding sessions based on session boundaries."""
        if len(sessions) <= 1:
            return [exchanges]
        
        # Find session boundaries based on SELECT + INITIALIZE UPDATE pattern
        session_starts = []
        for i, exchange in enumerate(exchanges):
            if exchange.command.startswith('00A404'):  # SELECT
                # Look ahead for INITIALIZE UPDATE
                if i + 1 < len(exchanges) and exchanges[i + 1].command.startswith('8050'):
                    session_starts.append(i)
        
        # If we don't find clear boundaries, fall back to equal division
        if len(session_starts) != len(sessions):
            print(f"Warning: Could not detect {len(sessions)} session boundaries, using equal division")
            exchanges_per_session = len(exchanges) // len(sessions)
            remainder = len(exchanges) % len(sessions)
            
            partitioned = []
            start_idx = 0
            
            for i in range(len(sessions)):
                session_size = exchanges_per_session + (1 if i < remainder else 0)
                end_idx = start_idx + session_size
                
                if end_idx > len(exchanges):
                    end_idx = len(exchanges)
                
                partitioned.append(exchanges[start_idx:end_idx])
                start_idx = end_idx
            
            return partitioned
        
        # Use detected session boundaries
        partitioned = []
        for i, start in enumerate(session_starts):
            end = session_starts[i + 1] if i + 1 < len(session_starts) else len(exchanges)
            partitioned.append(exchanges[start:end])
        
        return partitioned
    
    def _extract_card_info(self, exchanges: List[Exchange]) -> CardInfo:
        """Extract card information from SELECT response."""
        default_atr = "3BD518FF8191FE1FC38073C821100A"
        default_isd = "A000000151000000"
        
        for exchange in exchanges:
            if "SELECT" in exchange.description and exchange.response.startswith("6F"):
                # Try to extract AID from FCI template
                if "A000000151000000" in exchange.response:
                    return CardInfo(
                        atr=default_atr,
                        isd_aid="A000000151000000",
                        card_type="GP_COMPLIANT"
                    )
        
        return CardInfo(atr=default_atr, isd_aid=default_isd)
    
    def _generate_test_hints(self, exchanges: List[Exchange], sessions: List[SessionData]) -> Dict[str, Any]:
        """Generate test hints for testable operations."""
        testable_operations = []
        
        # Parse actual SCP version from INITIALIZE UPDATE response
        actual_scp_version = None
        for exchange in exchanges:
            if "INITIALIZE UPDATE" in exchange.description:
                parsed_info = self.parser._parse_initialize_update_response(exchange.response)
                actual_scp_version = parsed_info.get('scp_version')
                break
        
        for i, exchange in enumerate(exchanges):
            if "SELECT" in exchange.description:
                testable_operations.append({
                    "name": "select",
                    "exchange_index": i,
                    "verify": ["aid"]
                })
            elif "INITIALIZE UPDATE" in exchange.description:
                testable_operations.append({
                    "name": "initialize_update", 
                    "exchange_index": i,
                    "verify": ["key_derivation", "card_cryptogram"]
                })
            elif "EXTERNAL AUTHENTICATE" in exchange.description:
                testable_operations.append({
                    "name": "external_authenticate",
                    "exchange_index": i, 
                    "verify": ["secure_channel"]
                })
            elif "DELETE" in exchange.description:
                # Check if DELETE returns 6A88 (Data not found) - this is valid
                verify_list = ["delete_command"]
                if exchange.response.startswith("6A88"):
                    verify_list.append("delete_response_6a88_valid")
                testable_operations.append({
                    "name": "delete",
                    "exchange_index": i,
                    "verify": verify_list
                })
        
        return {
            "testable_operations": testable_operations,
            "scp_version": actual_scp_version or (sessions[0].scp_version if sessions else None)
        }
    
    def _metadata_to_dict(self, metadata: TraceMetadata) -> Dict[str, Any]:
        """Convert metadata to dictionary format."""
        return {
            "source": {
                "file": metadata.source_file,
                "type": metadata.format_type,
                "generated": metadata.generated,
                "tool_version": metadata.tool_version
            },
            "card": asdict(metadata.card),
            "warnings": metadata.warnings
        }
    
    def _exchange_to_dict(self, exchange: Exchange) -> Dict[str, Any]:
        """Convert exchange to dictionary format."""
        result = {
            "command": exchange.command,
            "response": exchange.response,
            "description": exchange.description
        }
        if exchange.response_time_ms:
            result["response_time_ms"] = exchange.response_time_ms
        return result
    
    def _session_to_dict(self, session: SessionData) -> Dict[str, Any]:
        """Convert session to dictionary format."""
        return {
            "scp_version": session.scp_version,
            "implementation": session.implementation,
            "key_version": session.key_version,
            "host_challenge": session.host_challenge,
            "card_challenge": session.card_challenge,
            "sequence_counter": session.sequence_counter,
            "key_diversification_data": session.key_diversification_data,
            "card_cryptogram": session.card_cryptogram,
            "host_cryptogram": session.host_cryptogram
        }


def main():
    parser = argparse.ArgumentParser(description='Unified trace converter with rich extraction')
    parser.add_argument('input', help='Input trace file(s)')
    parser.add_argument('-o', '--output', help='Output JSON file (auto-generated if not specified)')
    parser.add_argument('--batch', action='store_true', help='Process multiple files')
    
    args = parser.parse_args()
    
    converter = TraceConverter()
    
    if args.batch or '*' in args.input:
        # Batch processing
        input_files = Path('.').glob(args.input) if '*' in args.input else [Path(args.input)]
        for input_file in input_files:
            output_file = args.output or str(input_file.with_suffix('.json'))
            try:
                converter.convert_file(str(input_file), output_file)
            except Exception as e:
                print(f"Error processing {input_file}: {e}")
    else:
        # Single file
        output_file = args.output or str(Path(args.input).with_suffix('.json'))
        converter.convert_file(args.input, output_file)


if __name__ == "__main__":
    main()