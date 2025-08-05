#!/usr/bin/env python3
"""
Convert GlobalPlatform Card Specification PDF to LLM-friendly format.
Supports both LlamaParse and Unstructured for PDF processing.
"""

import os
import sys
import argparse
from pathlib import Path

def convert_with_llamaparse(pdf_path, output_path):
    """Convert PDF using LlamaParse."""
    try:
        from llama_parse import LlamaParse
        
        # You'll need to set your API key
        # os.environ["LLAMA_CLOUD_API_KEY"] = "your-api-key"
        
        parser = LlamaParse(
            result_type="markdown",  # or "text"
            num_workers=4,
            verbose=True,
            language="en",
        )
        
        print(f"Parsing {pdf_path} with LlamaParse...")
        documents = parser.load_data(pdf_path)
        
        # Combine all pages
        full_text = "\n\n".join([doc.text for doc in documents])
        
        # Save to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(full_text)
            
        print(f"Saved to {output_path}")
        return True
        
    except ImportError:
        print("LlamaParse not installed. Install with: pip install llama-parse")
        return False
    except Exception as e:
        print(f"Error with LlamaParse: {e}")
        return False

def convert_with_unstructured(pdf_path, output_path):
    """Convert PDF using Unstructured."""
    try:
        from unstructured.partition.pdf import partition_pdf
        from unstructured.chunking.title import chunk_by_title
        from unstructured.staging.base import convert_to_markdown
        
        print(f"Parsing {pdf_path} with Unstructured...")
        
        # Extract elements from PDF
        elements = partition_pdf(
            filename=pdf_path,
            strategy="hi_res",  # Use high resolution strategy for better results
            infer_table_structure=True,  # Extract tables
            extract_images_in_pdf=False,  # Skip images for text-only output
            include_page_breaks=True,
        )
        
        # Convert to markdown
        markdown_text = convert_to_markdown(elements)
        
        # Optionally chunk by title for better structure
        # chunks = chunk_by_title(elements, max_characters=4000)
        
        # Save to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(markdown_text)
            
        print(f"Saved to {output_path}")
        return True
        
    except ImportError:
        print("Unstructured not installed. Install with: pip install unstructured[pdf]")
        return False
    except Exception as e:
        print(f"Error with Unstructured: {e}")
        return False

def create_summary_metadata(pdf_path, output_dir):
    """Create a metadata file with document structure summary."""
    metadata_path = Path(output_dir) / "gp_card_spec_metadata.md"
    
    metadata = """# GlobalPlatform Card Specification v2.3.1 - Document Structure

## Overview
This document contains the GlobalPlatform Card Specification version 2.3.1, which defines:
- Card architecture and lifecycle
- Security protocols (SCP01, SCP02, SCP03)
- APDU commands and responses
- Data structures and TLV formats
- Cryptographic operations
- Application management

## Key Sections for Implementation

### 1. Card Data Structures (Section 7)
- CPLC Data (7.4.2)
- Card Data (Appendix F)
- Card Capabilities (Appendix H)
- Key Information Template (9.3.3.1)

### 2. Security Protocols (Section 10)
- SCP02 Implementation (10.6)
- SCP03 Implementation (10.7)
- Key Derivation (10.8)

### 3. APDU Commands (Section 11)
- SELECT (11.2)
- INITIALIZE UPDATE (11.4)
- EXTERNAL AUTHENTICATE (11.5)
- GET DATA (11.3)
- INSTALL (11.6)
- LOAD (11.7)

### 4. Data Encoding
- TLV Structure (throughout)
- OID Definitions (Appendix F)
- Status Words (Appendix A)

## Usage Notes
- Search for specific tag values (e.g., "tag '67'" for card capabilities)
- Command structures are in Section 11
- Security protocol details in Section 10
- Data object definitions in Appendices
"""
    
    with open(metadata_path, 'w') as f:
        f.write(metadata)
    
    print(f"Created metadata file: {metadata_path}")

def main():
    parser = argparse.ArgumentParser(description="Convert GP Card Spec PDF to LLM format")
    parser.add_argument("--method", choices=["llamaparse", "unstructured", "both"], 
                        default="unstructured", help="Conversion method to use")
    parser.add_argument("--pdf", default="docs/GPC_CardSpecification_v2.3.1_PublicRelease_CC.pdf",
                        help="Path to PDF file")
    parser.add_argument("--output-dir", default="docs/parsed", 
                        help="Output directory for converted files")
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    pdf_path = Path(args.pdf)
    if not pdf_path.exists():
        print(f"Error: PDF not found at {pdf_path}")
        sys.exit(1)
    
    # Create metadata
    create_summary_metadata(pdf_path, output_dir)
    
    # Convert based on method
    success = False
    
    if args.method in ["llamaparse", "both"]:
        output_path = output_dir / "gp_card_spec_llamaparse.md"
        if convert_with_llamaparse(str(pdf_path), str(output_path)):
            success = True
    
    if args.method in ["unstructured", "both"]:
        output_path = output_dir / "gp_card_spec_unstructured.md"
        if convert_with_unstructured(str(pdf_path), str(output_path)):
            success = True
    
    if not success:
        print("\nFailed to convert PDF. Please install required libraries:")
        print("  pip install llama-parse  # For LlamaParse")
        print("  pip install unstructured[pdf]  # For Unstructured")
        print("\nFor LlamaParse, you'll also need to set LLAMA_CLOUD_API_KEY")
        sys.exit(1)
    
    print("\nConversion complete!")

if __name__ == "__main__":
    main()