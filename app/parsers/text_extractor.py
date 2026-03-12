"""
Text extractor for PDF, markdown, and document files.

Supported formats: .pdf, .txt, .md, .docx, .html
Outputs doc.* fields for metadata, content, and analysis.
"""

from pathlib import Path
from typing import Dict, Any, List
import re
import time

from app.logging.logger import get_logger

logger = get_logger("parsers.text_extractor")

# Pre-compiled regex patterns
_RE_MARKDOWN_TITLE = re.compile(r'^#\s+(.+)$', re.MULTILINE)
_RE_MD_HEADING = re.compile(r'^#{1,3}\s+(.+)$', re.MULTILINE)
_RE_MD_FORMAT = re.compile(r'[*`\[\]()\-_>|]')
_RE_WHITESPACE = re.compile(r'\s+')
_RE_URLS = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
_RE_CODE_BLOCKS = re.compile(r'```[\w]*\n(.*?)```', re.DOTALL)
_RE_INLINE_CODE = re.compile(r'`([^`]+)`')
_RE_ENTITIES = re.compile(r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b')
_RE_CITATIONS = re.compile(r'\[(\d+)\]')
_RE_SEE_REFS = re.compile(r'see\s+([A-Z][^.!?]+)', re.IGNORECASE)
_RE_FILE_REFS = re.compile(r'[\w/]+\.(?:py|js|java|go|rs|txt|md|pdf|csv)')
_RE_API_PATHS = re.compile(r'/[\w/\-]+')
_RE_API_PREFIX = re.compile(r'/api|/v\d')
_RE_REQUIREMENTS = [
    re.compile(r'(?:must|shall|should|require[sd]?)\s+([^.!?]+)[.!?]', re.IGNORECASE),
    re.compile(r'requirement[s]?:\s*([^.!?\n]+)', re.IGNORECASE)
]
_RE_RISKS = [
    re.compile(r'risk[s]?:\s*([^.!?\n]+)', re.IGNORECASE),
    re.compile(r'(?:potential|possible)\s+(?:risk|issue|problem):\s*([^.!?\n]+)', re.IGNORECASE)
]
_RE_DECISIONS = [
    re.compile(r'decision[s]?:\s*([^.!?\n]+)', re.IGNORECASE),
    re.compile(r'(?:we|team)\s+decided\s+(?:to|that)\s+([^.!?]+)', re.IGNORECASE)
]
_RE_ASSUMPTIONS = [
    re.compile(r'assum(?:e|ption)[s]?:\s*([^.!?\n]+)', re.IGNORECASE),
    re.compile(r'(?:we|it is)\s+assum(?:e|ed)\s+(?:that)?\s*([^.!?]+)', re.IGNORECASE)
]
_RE_CONSTRAINTS = [
    re.compile(r'constraint[s]?:\s*([^.!?\n]+)', re.IGNORECASE),
    re.compile(r'(?:limited|restricted)\s+(?:to|by)\s+([^.!?]+)', re.IGNORECASE)
]


_docling_converter = None


def _get_docling_converter():
    global _docling_converter
    if _docling_converter is None:
        from docling.document_converter import DocumentConverter
        _docling_converter = DocumentConverter()
    return _docling_converter


def extract_text(path: Path) -> Dict[str, Any]:
    start_time = time.time()
    suffix = path.suffix.lower()

    if suffix == ".pdf":
        result = _extract_pdf(path)
    elif suffix == ".txt":
        result = _extract_txt(path)
    elif suffix == ".md":
        result = _extract_markdown(path)
    elif suffix == ".docx":
        result = _extract_docx(path)
    elif suffix == ".html":
        result = _extract_html(path)
    else:
        raise ValueError(f"Unsupported document format: {suffix}")

    duration_ms = (time.time() - start_time) * 1000
    logger.info("Text extraction complete", extra={
        "file": str(path),
        "format": suffix,
        "extract_duration_ms": duration_ms,
        "fields_extracted": len([k for k, v in result.items() if v])
    })
    return result


def _extract_pdf(path: Path) -> Dict[str, Any]:
    try:
        converter = _get_docling_converter()
        result = converter.convert(str(path))
        text = result.document.export_to_markdown()
        metadata = {
            "title": getattr(result.document, "title", ""),
            "author": getattr(result.document, "author", ""),
        }
    except (ImportError, Exception) as e:
        logger.warning(f"Docling failed, falling back to pypdf: {e}")
        from pypdf import PdfReader
        with open(path, 'rb') as f:
            reader = PdfReader(f)
            try:
                metadata = reader.metadata or {}
                text = ""
                for page in reader.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text + "\n"
                metadata = {
                    "title": metadata.get("/Title", ""),
                    "author": metadata.get("/Author", ""),
                }
            finally:
                reader.close()

    analysis = _analyze_text(text)
    return {
        "doc.sections": _extract_paragraphs(text),
        "doc.title": metadata.get("title", ""),
        "doc.author": metadata.get("author", ""),
        **analysis
    }


def _extract_txt(path: Path) -> Dict[str, Any]:
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()

    analysis = _analyze_text(text)
    return {
        "doc.sections": _extract_paragraphs(text),
        "doc.title": path.stem,
        **analysis
    }


def _extract_markdown(path: Path) -> Dict[str, Any]:
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()

    title_match = _RE_MARKDOWN_TITLE.search(text)
    title = title_match.group(1) if title_match else path.stem

    analysis = _analyze_text(text)
    return {
        "doc.sections": _extract_sections(text),
        "doc.title": title,
        **analysis
    }


def _extract_docx(path: Path) -> Dict[str, Any]:
    import docx
    doc = docx.Document(path)
    core_props = doc.core_properties
    text = "\n".join([para.text for para in doc.paragraphs])

    analysis = _analyze_text(text)
    return {
        "doc.sections": _extract_paragraphs(text),
        "doc.title": core_props.title or path.stem,
        "doc.author": core_props.author or "",
        "doc.date": str(core_props.created) if core_props.created else "",
        **analysis
    }


def _extract_html(path: Path) -> Dict[str, Any]:
    from bs4 import BeautifulSoup
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        html = f.read()

    soup = BeautifulSoup(html, 'html.parser')
    title_tag = soup.find('title')
    title = title_tag.get_text() if title_tag else path.stem

    for script in soup(["script", "style"]):
        script.decompose()
    text = soup.get_text()

    analysis = _analyze_text(text)
    return {
        "doc.sections": _extract_paragraphs(text),
        "doc.title": title,
        **analysis
    }


def _analyze_text(text: str) -> Dict[str, Any]:
    return {
        "doc.urls": _extract_urls(text),
        "doc.code_snippets": _extract_code_snippets(text),
        "doc.key_requirements": _extract_requirements(text),
        "doc.entities": _extract_entities(text),
        "doc.references": _extract_references(text),
        "doc.related_files": _extract_file_references(text),
        "doc.api_endpoints": _extract_api_endpoints(text),
        "doc.questions": _extract_questions(text),
        "doc.risks": _extract_risks(text),
        "doc.decisions": _extract_decisions(text),
        "doc.assumptions": _extract_assumptions(text),
        "doc.constraints": _extract_constraints(text),
    }


def _extract_sections(text: str) -> List[str]:
    """Split markdown by headings into heading+body chunks."""
    sections = []
    current_heading = ""
    current_body: List[str] = []

    def flush():
        body = _RE_MD_FORMAT.sub(' ', '\n'.join(current_body))
        body = _RE_WHITESPACE.sub(' ', body).strip()
        chunk = f"{current_heading}\n{body}".strip() if body else current_heading
        if chunk:
            sections.append(chunk[:1500])

    for line in text.split('\n'):
        m = re.match(r'^#{1,3}\s+(.+)$', line)
        if m:
            if current_heading or current_body:
                flush()
            current_heading = m.group(1).strip()
            current_body = []
        else:
            current_body.append(line)

    if current_heading or current_body:
        flush()

    return sections


def _extract_paragraphs(text: str) -> List[str]:
    """Split plain text into paragraph chunks."""
    paras = [p.strip() for p in re.split(r'\n{2,}', text) if p.strip()]
    return [_RE_WHITESPACE.sub(' ', p)[:1500] for p in paras[:20]]


def _extract_urls(text: str) -> List[str]:
    return list(set(_RE_URLS.findall(text)))[:20]


def _extract_code_snippets(text: str) -> List[str]:
    snippets = []
    snippets.extend(_RE_CODE_BLOCKS.findall(text))
    snippets.extend(_RE_INLINE_CODE.findall(text))
    return snippets[:10]


def _extract_requirements(text: str) -> List[str]:
    requirements = []
    for pattern in _RE_REQUIREMENTS:
        requirements.extend(pattern.findall(text))
    return [req.strip() for req in requirements][:10]


def _extract_entities(text: str) -> List[str]:
    return list(set(_RE_ENTITIES.findall(text)))[:20]


def _extract_references(text: str) -> List[str]:
    refs = []
    refs.extend(_RE_CITATIONS.findall(text))
    refs.extend(_RE_SEE_REFS.findall(text))
    return refs[:10]


def _extract_file_references(text: str) -> List[str]:
    return list(set(_RE_FILE_REFS.findall(text)))[:20]


def _extract_api_endpoints(text: str) -> List[str]:
    endpoints = _RE_API_PATHS.findall(text)
    return list(set(e for e in endpoints if _RE_API_PREFIX.match(e)))[:10]


def _extract_questions(text: str) -> List[str]:
    questions = re.findall(r'([^.!?]*\?)', text)
    return [q.strip() for q in questions if len(q.strip()) > 10][:10]


def _extract_risks(text: str) -> List[str]:
    risks = []
    for pattern in _RE_RISKS:
        risks.extend(pattern.findall(text))
    return [r.strip() for r in risks][:10]


def _extract_decisions(text: str) -> List[str]:
    decisions = []
    for pattern in _RE_DECISIONS:
        decisions.extend(pattern.findall(text))
    return [d.strip() for d in decisions][:10]


def _extract_assumptions(text: str) -> List[str]:
    assumptions = []
    for pattern in _RE_ASSUMPTIONS:
        assumptions.extend(pattern.findall(text))
    return [a.strip() for a in assumptions][:10]


def _extract_constraints(text: str) -> List[str]:
    constraints = []
    for pattern in _RE_CONSTRAINTS:
        constraints.extend(pattern.findall(text))
    return [c.strip() for c in constraints][:10]


def _empty_result() -> Dict[str, Any]:
    return {
        "doc.title": "",
        "doc.author": "",
        "doc.date": "",
        "doc.version": "",
        "doc.language": "",
        "doc.sections": [],
        "doc.urls": [],
        "doc.code_snippets": [],
        "doc.key_requirements": [],
        "doc.entities": [],
        "doc.references": [],
        "doc.related_files": [],
        "doc.api_endpoints": [],
        "doc.questions": [],
        "doc.risks": [],
        "doc.decisions": [],
        "doc.assumptions": [],  
        "doc.constraints": [],
    }
