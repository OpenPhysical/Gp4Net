import pymupdf4llm

md_text = pymupdf4llm.to_markdown("jcop4-admin-sanitized.pdf")

# now work with the markdown text, e.g. store as a UTF8-encoded file
import pathlib
pathlib.Path("jcop4-admin-sanitized.md").write_bytes(md_text.encode())
