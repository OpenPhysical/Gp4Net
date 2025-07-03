#!/usr/bin/env python3
"""
Enhanced trace converter that outputs structured JSON with rich metadata.
Supports GP Pro and GPShell formats with operation detection and session analysis.

Usage:
    python convert_trace_json.py gp_pro input.txt output.json
    python convert_trace_json.py gpshell input.log output.json
"""

import sys
import json
import re
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime
import argparse

@dataclass
class SourceInfo:
    file: str
    type: str
    generated: str
    tool_version: str

@dataclass
class CplcData:
    ic_fabricator: str
    ic_type: str
    os_id: str
    ic_serial: str

@dataclass
class CardInfo:
    atr: str
    isd_aid: str
    card_type: str
    cplc: Optional[CplcData] = None

@dataclass
class DerivationData:
    kdd: str
    host_challenge: str
    card_challenge: str
    card_cryptogram: str

@dataclass
class SessionKeys:
    s_enc: str
    s_mac: str
    s_rmac: str

@dataclass
class SessionMetadata:
    session_id: str
    scp_version: int
    scp_implementation: str
    key_version: int
    security_level: str
    key_diversification: str
    host_challenge: str
    card_challenge: str
    sequence_counter: str
    derivation_data: DerivationData
    session_keys: Optional[SessionKeys]
    operations: List[str]

@dataclass
class Operation:
    description: str
    session_id: str
    start_exchange: int
    end_exchange: int
    commands: List[str]
    expected_cli: str
    package_aid: Optional[str] = None
    applet_aid: Optional[str] = None
    target_aid: Optional[str] = None

@dataclass
class UsageExample:
    description: str
    command: str

@dataclass
class ScpData:
    host_challenge: Optional[str] = None
    card_challenge: Optional[str] = None
    card_cryptogram: Optional[str] = None
    key_version: Optional[int] = None
    scp_id: Optional[str] = None
    host_cryptogram: Optional[str] = None
    session_established: Optional[bool] = None

@dataclass
class Exchange:
    index: int
    operation: str
    session_id: str
    step_in_operation: int
    command: str
    response: str
    response_time_ms: int
    description: str
    source_line: int
    secure_messaging: bool
    scp_data: Optional[ScpData] = None

class ApduAnalyzer:
    """Analyzes APDU commands to extract semantic information."""
    
    COMMAND_DESCRIPTIONS = {
        '00A4': 'SELECT',
        '80CA': 'GET DATA',
        '80F2': 'GET STATUS', 
        '8050': 'INITIALIZE UPDATE',
        '8482': 'EXTERNAL AUTHENTICATE',
        '80E6': 'INSTALL',
        '80E8': 'LOAD',
        '80E4': 'DELETE'
    }
    
    GET_DATA_TAGS = {
        '9F7F': 'CPLC',
        '0042': 'IIN',
        '0045': 'CIN', 
        '00CF': 'KDD',
        '00C1': 'SSC',
        '0066': 'CARD DATA',
        '0067': 'CARD CAPABILITIES',
        '00E0': 'KEY INFORMATION'
    }
    
    def get_command_description(self, command_hex: str) -> str:
        """Get human-readable description of APDU command."""
        if len(command_hex) < 4:
            return "UNKNOWN"
            
        cla_ins = command_hex[:4]
        ins = command_hex[2:4]
        
        if ins in self.COMMAND_DESCRIPTIONS:
            base_desc = self.COMMAND_DESCRIPTIONS[ins]
            
            # Special handling for GET DATA
            if ins == '80CA' and len(command_hex) >= 8:
                tag = command_hex[4:8]
                if tag in self.GET_DATA_TAGS:
                    return f"GET {self.GET_DATA_TAGS[tag]}"
                return f"GET DATA (tag {tag})"
            
            # Special handling for INSTALL
            if ins == '80E6' and len(command_hex) >= 6:
                p1 = command_hex[4:6]
                if p1 == '02':
                    return "INSTALL [for load]"
                elif p1 == '04':
                    return "INSTALL [for install and make selectable]"
                elif p1 == '0C':
                    return "INSTALL [for install]"
                return f"INSTALL (P1={p1})"
            
            return base_desc
        
        return f"UNKNOWN (INS={ins})"
    
    def is_secure_messaging(self, command_hex: str) -> bool:
        """Check if command uses secure messaging (CLA bit 2 set)."""
        if len(command_hex) < 2:
            return False
        cla = int(command_hex[:2], 16)
        return (cla & 0x04) != 0
    
    def extract_scp_data(self, command_hex: str, response_hex: str, description: str) -> Optional[ScpData]:
        """Extract SCP-specific data from commands and responses."""
        scp_data = ScpData()
        
        if "INITIALIZE UPDATE" in description:
            # Extract host challenge from command
            if len(command_hex) >= 20:  # 8050 + 00 + 00 + 08 + 8 bytes challenge + 00
                scp_data.host_challenge = command_hex[10:26]
            
            # Extract data from response
            if len(response_hex) >= 66 and response_hex.endswith("9000"):
                response_data = response_hex[:-4]
                if len(response_data) >= 64:  # SCP03 32-byte response
                    scp_data.key_version = int(response_data[20:22], 16)
                    scp_data.scp_id = response_data[22:24]
                    scp_data.card_challenge = response_data[30:46]
                    scp_data.card_cryptogram = response_data[46:62]
        
        elif "EXTERNAL AUTHENTICATE" in description:
            # Extract host cryptogram from command
            if len(command_hex) >= 20:  # 8482 + 01 + 00 + 10 + 16 bytes cryptogram
                scp_data.host_cryptogram = command_hex[12:44]
                scp_data.session_established = response_hex == "9000"
        
        # Return None if no SCP data was found
        if not any(getattr(scp_data, field) for field in scp_data.__dataclass_fields__):
            return None
            
        return scp_data

class OperationDetector:
    """Detects and categorizes operations within traces."""
    
    OPERATION_PATTERNS = {
        'info': {
            'indicators': ['SELECT', 'GET CPLC', 'GET CARD DATA', 'GET CAPABILITIES'],
            'cli_template': 'gp4net card info'
        },
        'list': {
            'indicators': ['GET STATUS'],
            'cli_template': 'gp4net applet list'
        },
        'secure_channel_establish': {
            'indicators': ['INITIALIZE UPDATE', 'EXTERNAL AUTHENTICATE'],
            'cli_template': 'gp4net card keys gp_test_keys'
        },
        'install_applet': {
            'indicators': ['INSTALL [for load]', 'LOAD', 'INSTALL [for install]'],
            'cli_template': 'gp4net applet install {package}.cap'
        },
        'uninstall': {
            'indicators': ['DELETE'],
            'cli_template': 'gp4net applet delete {aid}'
        }
    }
    
    def __init__(self):
        self.operation_counter = {}
    
    def detect_operation_type(self, exchange: Exchange) -> str:
        """Detect the operation type based on command description."""
        description = exchange.description
        
        # Check each operation pattern
        for op_type, pattern in self.OPERATION_PATTERNS.items():
            for indicator in pattern['indicators']:
                if indicator in description:
                    return op_type
        
        return 'unknown'
    
    def get_unique_operation_name(self, operation_type: str) -> str:
        """Generate unique operation name with numbering for duplicates."""
        if operation_type not in self.operation_counter:
            self.operation_counter[operation_type] = 1
            return operation_type
        else:
            self.operation_counter[operation_type] += 1
            return f"{operation_type}{self.operation_counter[operation_type]}"
    
    def analyze_trace(self, exchanges: List[Exchange]) -> Dict[str, Operation]:
        """Analyze exchanges and group them into operations."""
        operations = {}
        current_operation = None
        current_op_name = None
        operation_start = None
        
        for i, exchange in enumerate(exchanges):
            detected_op = self.detect_operation_type(exchange)
            
            if detected_op != current_operation:
                # Close previous operation
                if current_operation and current_op_name:
                    operations[current_op_name].end_exchange = i
                
                # Start new operation
                current_operation = detected_op
                current_op_name = self.get_unique_operation_name(detected_op)
                operation_start = i + 1
                
                operations[current_op_name] = Operation(
                    description=self.get_operation_description(detected_op),
                    session_id="session_1",  # Will be updated by session analyzer
                    start_exchange=operation_start,
                    end_exchange=i + 1,
                    commands=[],
                    expected_cli=self.OPERATION_PATTERNS.get(detected_op, {}).get('cli_template', 'gp4net unknown')
                )
            
            # Add command to current operation
            if current_op_name:
                if exchange.description not in operations[current_op_name].commands:
                    operations[current_op_name].commands.append(exchange.description)
                
                # Update exchange with operation info
                exchange.operation = current_op_name
                exchange.step_in_operation = len([e for e in exchanges[:i+1] if e.operation == current_op_name])
        
        # Close final operation
        if current_op_name:
            operations[current_op_name].end_exchange = len(exchanges)
        
        return operations
    
    def get_operation_description(self, operation_type: str) -> str:
        """Get human-readable description for operation type."""
        descriptions = {
            'info': 'Card information gathering',
            'list': 'List applications on card',
            'secure_channel_establish': 'SCP authentication',
            'install_applet': 'Install application package',
            'uninstall': 'Remove application',
            'unknown': 'Unknown operation'
        }
        return descriptions.get(operation_type, 'Unknown operation')

class SessionAnalyzer:
    """Analyzes traces to detect and characterize secure channel sessions."""
    
    def __init__(self):
        self.session_counter = 1
    
    def detect_sessions(self, exchanges: List[Exchange]) -> List[SessionMetadata]:
        """Detect session boundaries and extract session metadata."""
        sessions = []
        current_session = None
        
        for exchange in exchanges:
            # Detect new session start
            if "INITIALIZE UPDATE" in exchange.description:
                if current_session:
                    sessions.append(current_session)
                
                current_session = self.create_session_from_init_update(exchange)
            
            # Update session with additional data
            if current_session:
                self.update_session_data(current_session, exchange)
        
        # Add final session
        if current_session:
            sessions.append(current_session)
        
        return sessions
    
    def create_session_from_init_update(self, exchange: Exchange) -> SessionMetadata:
        """Create session metadata from INITIALIZE UPDATE exchange."""
        session_id = f"session_{self.session_counter}"
        self.session_counter += 1
        
        scp_data = exchange.scp_data
        derivation_data = None
        
        if scp_data:
            derivation_data = DerivationData(
                kdd="0370000000000000000001",  # Default, should be extracted
                host_challenge=scp_data.host_challenge or "",
                card_challenge=scp_data.card_challenge or "",
                card_cryptogram=scp_data.card_cryptogram or ""
            )
        
        return SessionMetadata(
            session_id=session_id,
            scp_version=3,  # Default, should be extracted from response
            scp_implementation="i=70",  # Default
            key_version=scp_data.key_version if scp_data else 1,
            security_level="C_MAC|R_MAC|C_ENC|R_ENC",
            key_diversification="none",
            host_challenge=scp_data.host_challenge if scp_data else "",
            card_challenge=scp_data.card_challenge if scp_data else "",
            sequence_counter="000001",
            derivation_data=derivation_data or DerivationData("", "", "", ""),
            session_keys=None,  # Would be calculated
            operations=[]
        )
    
    def update_session_data(self, session: SessionMetadata, exchange: Exchange) -> None:
        """Update session metadata with additional exchange data."""
        # Update session ID in exchange
        exchange.session_id = session.session_id
        
        # Add operation to session if not already present
        if exchange.operation and exchange.operation not in session.operations:
            session.operations.append(exchange.operation)

class GpProParser:
    """Parser for GP Pro trace format."""
    
    def __init__(self):
        self.command_pattern = re.compile(r'^A>> T=\d+ \([\d+]+\) ([0-9A-F\s]+)$')
        self.response_pattern = re.compile(r'^A<< \([\d+]+\) \((\d+)ms\) ([0-9A-F\s]+)$')
        self.analyzer = ApduAnalyzer()
    
    def parse_trace_file(self, filename: str) -> List[Exchange]:
        """Parse GP Pro trace file and extract exchanges."""
        exchanges = []
        current_command = None
        current_line = None
        
        with open(filename, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#') or line.startswith('[') or line.startswith('WARNING:'):
                    continue
                
                # Try to match command
                cmd_match = self.command_pattern.match(line)
                if cmd_match:
                    current_command = cmd_match.group(1).strip().replace(' ', '').upper()
                    current_line = line_num
                    continue
                
                # Try to match response
                resp_match = self.response_pattern.match(line)
                if resp_match and current_command:
                    response_time = int(resp_match.group(1))
                    response_data = resp_match.group(2).strip().replace(' ', '').upper()
                    
                    # Create exchange
                    description = self.analyzer.get_command_description(current_command)
                    secure_messaging = self.analyzer.is_secure_messaging(current_command)
                    scp_data = self.analyzer.extract_scp_data(current_command, response_data, description)
                    
                    exchange = Exchange(
                        index=len(exchanges) + 1,
                        operation="",  # Will be filled by operation detector
                        session_id="",  # Will be filled by session analyzer
                        step_in_operation=0,  # Will be calculated
                        command=current_command,
                        response=response_data,
                        response_time_ms=response_time,
                        description=description,
                        source_line=current_line,
                        secure_messaging=secure_messaging,
                        scp_data=scp_data
                    )
                    
                    exchanges.append(exchange)
                    current_command = None
                    current_line = None
        
        return exchanges

class GPShellParser:
    """Parser for GPShell log format."""
    
    def __init__(self):
        self.send_pattern = re.compile(r'Command --> ([0-9A-F\s]+)')
        self.recv_pattern = re.compile(r'Response <-- ([0-9A-F\s]+)')
        self.analyzer = ApduAnalyzer()
    
    def parse_trace_file(self, filename: str) -> List[Exchange]:
        """Parse GPShell log file and extract exchanges."""
        exchanges = []
        current_command = None
        current_line = None
        
        with open(filename, 'r') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                
                # Try to match command
                send_match = self.send_pattern.search(line)
                if send_match:
                    current_command = send_match.group(1).strip().replace(' ', '').upper()
                    current_line = line_num
                    continue
                
                # Try to match response  
                recv_match = self.recv_pattern.search(line)
                if recv_match and current_command:
                    response_data = recv_match.group(1).strip().replace(' ', '').upper()
                    
                    # Create exchange
                    description = self.analyzer.get_command_description(current_command)
                    secure_messaging = self.analyzer.is_secure_messaging(current_command)
                    scp_data = self.analyzer.extract_scp_data(current_command, response_data, description)
                    
                    exchange = Exchange(
                        index=len(exchanges) + 1,
                        operation="",  # Will be filled by operation detector
                        session_id="",  # Will be filled by session analyzer  
                        step_in_operation=0,  # Will be calculated
                        command=current_command,
                        response=response_data,
                        response_time_ms=20,  # Default, GPShell doesn't provide timing
                        description=description,
                        source_line=current_line,
                        secure_messaging=secure_messaging,
                        scp_data=scp_data
                    )
                    
                    exchanges.append(exchange)
                    current_command = None
                    current_line = None
        
        return exchanges

class MetadataExtractor:
    """Extracts metadata from parsed exchanges."""
    
    def extract_all(self, exchanges: List[Exchange], source_file: str, format_type: str) -> Dict[str, Any]:
        """Extract comprehensive metadata from exchanges."""
        return {
            "source": SourceInfo(
                file=source_file,
                type=format_type,
                generated=datetime.now().isoformat() + "Z",
                tool_version="gp4net-converter-1.0"
            ),
            "card": self.extract_card_info(exchanges),
            "sessions": []  # Will be populated by session analyzer
        }
    
    def extract_card_info(self, exchanges: List[Exchange]) -> CardInfo:
        """Extract card information from exchanges."""
        atr = "3BD518FF8191FE1FC38073C821100A"  # Default ATR
        isd_aid = self.find_isd_aid(exchanges)
        cplc_data = self.find_cplc_data(exchanges)
        
        return CardInfo(
            atr=atr,
            isd_aid=isd_aid,
            card_type=self.detect_card_type(cplc_data),
            cplc=cplc_data
        )
    
    def find_isd_aid(self, exchanges: List[Exchange]) -> str:
        """Find ISD AID from SELECT response."""
        for exchange in exchanges:
            if "SELECT" in exchange.description and exchange.response.startswith("6F"):
                # Parse FCI template to extract AID
                # This is a simplified extraction
                if "A000000151000000" in exchange.response:
                    return "A000000151000000"
        return "A000000151000000"  # Default ISD AID
    
    def find_cplc_data(self, exchanges: List[Exchange]) -> Optional[CplcData]:
        """Extract CPLC data from GET CPLC response."""
        for exchange in exchanges:
            if "GET CPLC" in exchange.description and len(exchange.response) > 20:
                response_data = exchange.response
                if response_data.startswith("9F7F") and response_data.endswith("9000"):
                    # Parse CPLC data
                    cplc_hex = response_data[6:-4]  # Remove tag+length and SW
                    if len(cplc_hex) >= 42:  # Minimum CPLC length
                        return CplcData(
                            ic_fabricator=cplc_hex[0:4],
                            ic_type=cplc_hex[4:8],
                            os_id=cplc_hex[8:12],
                            ic_serial=cplc_hex[24:32]
                        )
        return None
    
    def detect_card_type(self, cplc_data: Optional[CplcData]) -> str:
        """Detect card type based on CPLC data."""
        if cplc_data and cplc_data.ic_fabricator == "4790":
            return "NXP_P71"
        return "UNKNOWN"

class UsageExampleGenerator:
    """Generates usage examples for trace replay."""
    
    def generate_examples(self, operations: Dict[str, Operation]) -> List[UsageExample]:
        """Generate usage examples based on detected operations."""
        examples = []
        
        # Single operation examples
        for op_name, operation in operations.items():
            examples.append(UsageExample(
                description=f"{operation.description} only",
                command=f"{operation.expected_cli} -r 'lua:trace.lua?operations={op_name}'"
            ))
        
        # Workflow examples
        op_names = list(operations.keys())
        
        # Install workflow
        install_ops = [op for op in op_names if 'install' in op or 'secure_channel' in op or op == 'info']
        if len(install_ops) > 1:
            examples.append(UsageExample(
                description="Install workflow",
                command=f"gp4net applet install app.cap -r 'lua:trace.lua?operations={','.join(install_ops)}'"
            ))
        
        # Full workflow
        if len(op_names) > 2:
            examples.append(UsageExample(
                description="Complete workflow",
                command=f"gp4net script eval 'full_workflow()' -r 'lua:trace.lua?operations={','.join(op_names)}'"
            ))
        
        return examples

class TraceConverter:
    """Main converter class that orchestrates the conversion process."""
    
    def __init__(self):
        self.gp_pro_parser = GpProParser()
        self.gpshell_parser = GPShellParser()
        self.operation_detector = OperationDetector()
        self.session_analyzer = SessionAnalyzer()
        self.metadata_extractor = MetadataExtractor()
        self.usage_generator = UsageExampleGenerator()
    
    def convert_to_json(self, input_file: str, output_file: str, format_type: str) -> None:
        """Convert trace file to JSON format with rich metadata."""
        print(f"Converting {format_type} trace: {input_file}")
        
        # Parse trace based on format
        if format_type == 'gp_pro':
            exchanges = self.gp_pro_parser.parse_trace_file(input_file)
        elif format_type == 'gpshell':
            exchanges = self.gpshell_parser.parse_trace_file(input_file)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
        
        print(f"Found {len(exchanges)} APDU exchanges")
        
        # Detect operations
        operations = self.operation_detector.analyze_trace(exchanges)
        print(f"Detected operations: {', '.join(operations.keys())}")
        
        # Analyze sessions
        sessions = self.session_analyzer.detect_sessions(exchanges)
        print(f"Detected {len(sessions)} session(s)")
        
        # Link operations to sessions
        self.link_operations_to_sessions(operations, sessions)
        
        # Extract metadata
        metadata = self.metadata_extractor.extract_all(exchanges, input_file, format_type)
        metadata["sessions"] = sessions
        
        # Generate usage examples
        usage_examples = self.usage_generator.generate_examples(operations)
        
        # Build final JSON structure
        trace_data = {
            "metadata": metadata,
            "operations": operations,
            "usage_examples": usage_examples,
            "exchanges": exchanges
        }
        
        # Convert to JSON-serializable format
        json_data = self.convert_to_json_serializable(trace_data)
        
        # Write JSON file
        with open(output_file, 'w') as f:
            json.dump(json_data, f, indent=2)
        
        print(f"Generated JSON trace: {output_file}")
        self.print_summary(json_data)
    
    def link_operations_to_sessions(self, operations: Dict[str, Operation], sessions: List[SessionMetadata]) -> None:
        """Link operations to their corresponding sessions."""
        # Simple implementation: assign operations to sessions based on session list
        session_ops = {}
        for session in sessions:
            session_ops[session.session_id] = session.operations
        
        for op_name, operation in operations.items():
            # Find which session contains this operation
            for session in sessions:
                if op_name in session.operations:
                    operation.session_id = session.session_id
                    break
    
    def convert_to_json_serializable(self, data: Any) -> Any:
        """Convert dataclass objects to JSON-serializable format."""
        if hasattr(data, '__dataclass_fields__'):
            return asdict(data)
        elif isinstance(data, dict):
            return {k: self.convert_to_json_serializable(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.convert_to_json_serializable(item) for item in data]
        else:
            return data
    
    def print_summary(self, json_data: Dict[str, Any]) -> None:
        """Print conversion summary."""
        print("\nConversion Summary:")
        print(f"  Source: {json_data['metadata']['source']['file']}")
        print(f"  Format: {json_data['metadata']['source']['type']}")
        print(f"  Total exchanges: {len(json_data['exchanges'])}")
        print(f"  Operations: {len(json_data['operations'])}")
        print(f"  Sessions: {len(json_data['metadata']['sessions'])}")
        print(f"  Usage examples: {len(json_data['usage_examples'])}")

def main():
    parser = argparse.ArgumentParser(description='Convert trace files to JSON format with rich metadata')
    parser.add_argument('format', choices=['gp_pro', 'gpshell'], help='Trace format type')
    parser.add_argument('input', help='Input trace file')
    parser.add_argument('output', help='Output JSON file')
    
    args = parser.parse_args()
    
    try:
        converter = TraceConverter()
        converter.convert_to_json(args.input, args.output, args.format)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()