#!/usr/bin/env python3
"""
Convert GlobalPlatform Card Specification PDF to LLM-friendly format using pymupdf4llm.
"""

import sys
from pathlib import Path

def convert_with_pymupdf4llm(pdf_path, output_path):
    """Convert PDF using pymupdf4llm."""
    try:
        import pymupdf4llm
        
        print(f"Converting {pdf_path} with pymupdf4llm...")
        
        # Convert PDF to markdown
        md_text = pymupdf4llm.to_markdown(
            pdf_path,
            write_images=False,  # Skip images for text-only output
            page_chunks=False,   # Don't split by pages
            hdr_info=True,       # Include header info
        )
        
        # Save to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md_text)
            
        print(f"Saved to {output_path}")
        return True
        
    except ImportError:
        print("pymupdf4llm not installed. Install with: pip install pymupdf4llm")
        return False
    except Exception as e:
        print(f"Error with pymupdf4llm: {e}")
        return False

def main():
    # Check for command line argument
    if len(sys.argv) > 1:
        pdf_path = Path(sys.argv[1])
        # Generate output filename based on input
        output_filename = pdf_path.stem + "_pymupdf4llm.md"
    else:
        pdf_path = Path("docs/GPC_CardSpecification_v2.3.1_PublicRelease_CC.pdf")
        output_filename = "gp_card_spec_pymupdf4llm.md"
    
    output_dir = Path("docs/parsed")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if not pdf_path.exists():
        print(f"Error: PDF not found at {pdf_path}")
        sys.exit(1)
    
    # Convert with pymupdf4llm
    output_path = output_dir / output_filename
    
    if convert_with_pymupdf4llm(str(pdf_path), str(output_path)):
        print("\nConversion complete!")
        print(f"Output saved to: {output_path}")
        
        # Show file size
        size_mb = output_path.stat().st_size / (1024 * 1024)
        print(f"File size: {size_mb:.2f} MB")
    else:
        print("\nConversion failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()