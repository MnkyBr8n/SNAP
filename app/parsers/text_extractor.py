"""
Text extractor for PDF, markdown, and document files.

Supported formats: .pdf, .txt, .md, .docx, .html
Outputs doc.* fields for metadata, content, and analysis.
"""

from pathlib import Path
from typing import Dict, Any, List
from collections import Counter
import re
import time

from app.logging.logger import get_logger

logger = get_logger("parsers.text_extractor")

# Pre-compiled regex patterns for performance
_RE_MARKDOWN_TITLE = re.compile(r'^#\s+(.+)$', re.MULTILINE)
_RE_MARKDOWN_SYNTAX = re.compile(r'[#*`\[\]()]')
_RE_WHITESPACE = re.compile(r'\s+')
_RE_KEY_CONCEPTS = re.compile(r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b')
_RE_SNAKE_CASE = re.compile(r'\b[a-z]+(?:_[a-z]+)+\b')
_RE_CAMEL_CASE = re.compile(r'\b[a-z]+[A-Z][a-zA-Z]*\b')
_RE_ACRONYMS = re.compile(r'\b[A-Z]{2,}\b')
_RE_URLS = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
_RE_CODE_BLOCKS = re.compile(r'```[\w]*\n(.*?)```', re.DOTALL)
_RE_INLINE_CODE = re.compile(r'`([^`]+)`')
_RE_ENTITIES = re.compile(r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)+\b')
_RE_CITATIONS = re.compile(r'\[(\d+)\]')
_RE_SEE_REFS = re.compile(r'see\s+([A-Z][^.!?]+)', re.IGNORECASE)
_RE_FILE_REFS = re.compile(r'[\w/]+\.(?:py|js|java|go|rs|txt|md|pdf|csv)')
_RE_API_PATHS = re.compile(r'/[\w/\-]+')
_RE_API_PREFIX = re.compile(r'/api|/v\d')
_RE_QUESTIONS = re.compile(r'([^.!?]*\?)')
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


def extract_text(path: Path) -> Dict[str, Any]:
    """
    Extract text and metadata from document files.
    
    Args:
        path: Path to document file
    
    Returns:
        Dict with field_id keys matching master_notebook.yaml
    """
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
    """Extract text from PDF using pypdf."""
    from pypdf import PdfReader  # raises ImportError if not installed

    with open(path, 'rb') as f:
        reader = PdfReader(f)

        # Extract metadata
        metadata = reader.metadata or {}

        # Extract text from all pages
        text = ""
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text += page_text + "\n"

    analysis = _analyze_text(text)

    return {
        "doc.title": metadata.get("/Title", ""),
        "doc.author": metadata.get("/Author", ""),
        "doc.date": metadata.get("/CreationDate", ""),
        "doc.summary": _generate_summary(text),
        **analysis
    }


def _extract_txt(path: Path) -> Dict[str, Any]:
    """Extract text from plain text file."""
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()

    analysis = _analyze_text(text)

    return {
        "doc.title": path.stem,
        "doc.summary": _generate_summary(text),
        **analysis
    }


def _extract_markdown(path: Path) -> Dict[str, Any]:
    """Extract text from markdown file."""
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()

    # Extract title from first H1
    title_match = _RE_MARKDOWN_TITLE.search(text)
    title = title_match.group(1) if title_match else path.stem

    # Remove markdown syntax for analysis
    clean_text = _RE_MARKDOWN_SYNTAX.sub('', text)

    analysis = _analyze_text(clean_text)

    return {
        "doc.title": title,
        "doc.summary": _generate_summary(clean_text),
        **analysis
    }


def _extract_docx(path: Path) -> Dict[str, Any]:
    """Extract text from Word document."""
    import docx  # raises ImportError if not installed

    doc = docx.Document(path)

    # Extract metadata
    core_props = doc.core_properties

    # Extract text from paragraphs
    text = "\n".join([para.text for para in doc.paragraphs])

    analysis = _analyze_text(text)

    return {
        "doc.title": core_props.title or path.stem,
        "doc.author": core_props.author or "",
        "doc.date": str(core_props.created) if core_props.created else "",
        "doc.summary": _generate_summary(text),
        **analysis
    }


def _extract_html(path: Path) -> Dict[str, Any]:
    """Extract text from HTML file."""
    from bs4 import BeautifulSoup  # raises ImportError if not installed

    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        html = f.read()

    soup = BeautifulSoup(html, 'html.parser')

    # Extract title
    title_tag = soup.find('title')
    title = title_tag.get_text() if title_tag else path.stem

    # Extract text (remove scripts and styles)
    for script in soup(["script", "style"]):
        script.decompose()
    text = soup.get_text()

    analysis = _analyze_text(text)

    return {
        "doc.title": title,
        "doc.summary": _generate_summary(text),
        **analysis
    }


def _analyze_text(text: str) -> Dict[str, Any]:
    """
    Analyze text to extract structured information.
    
    Returns dict with doc.* fields.
    """
    return {
        "doc.key_concepts": _extract_key_concepts(text),
        "doc.technical_terms": _extract_technical_terms(text),
        "doc.acronyms": _extract_acronyms(text),
        "doc.urls": _extract_urls(text),
        "doc.code_snippets": _extract_code_snippets(text),
        "doc.key_requirements": _extract_requirements(text),
        "doc.entities": _extract_entities(text),
        "doc.references": _extract_references(text),
        "doc.related_files": _extract_file_references(text),
        "doc.api_endpoints": _extract_api_endpoints(text),
        "doc.open_questions": _extract_questions(text),
        "doc.risks": _extract_risks(text),
        "doc.decisions": _extract_decisions(text),
        "doc.assumptions": _extract_assumptions(text),
        "doc.constraints": _extract_constraints(text)
    }


def _generate_summary(text: str, max_length: int = 500) -> str:
    """Generate summary from text (first N characters)."""
    clean = _RE_WHITESPACE.sub(' ', text).strip()
    if len(clean) <= max_length:
        return clean
    return clean[:max_length] + "..."


def _extract_key_concepts(text: str) -> List[str]:
    """Extract key concepts (capitalized phrases)."""
    words = _RE_KEY_CONCEPTS.findall(text)
    common = Counter(words).most_common(10)
    return [word for word, count in common if count > 1]


def _extract_technical_terms(text: str) -> List[str]:
    """Extract technical terms (camelCase, snake_case, etc.)."""
    terms = set()
    terms.update(_RE_SNAKE_CASE.findall(text))
    terms.update(_RE_CAMEL_CASE.findall(text))
    return list(terms)[:20]


def _extract_acronyms(text: str) -> List[str]:
    """Extract acronyms (2+ capital letters)."""
    acronyms = set(_RE_ACRONYMS.findall(text))
    return list(acronyms)[:20]


def _extract_urls(text: str) -> List[str]:
    """Extract URLs."""
    urls = _RE_URLS.findall(text)
    return list(set(urls))[:20]


def _extract_code_snippets(text: str) -> List[str]:
    """Extract code blocks (markdown style or indented)."""
    snippets = []
    snippets.extend(_RE_CODE_BLOCKS.findall(text))
    snippets.extend(_RE_INLINE_CODE.findall(text))
    return snippets[:10]


def _extract_requirements(text: str) -> List[str]:
    """Extract requirements (MUST, SHALL, SHOULD patterns)."""
    requirements = []
    for pattern in _RE_REQUIREMENTS:
        requirements.extend(pattern.findall(text))
    return [req.strip() for req in requirements][:10]


def _extract_entities(text: str) -> List[str]:
    """Extract named entities (capitalized proper nouns)."""
    entities = _RE_ENTITIES.findall(text)
    return list(set(entities))[:20]


def _extract_references(text: str) -> List[str]:
    """Extract references (citations, links)."""
    refs = []
    refs.extend(_RE_CITATIONS.findall(text))
    refs.extend(_RE_SEE_REFS.findall(text))
    return refs[:10]


def _extract_file_references(text: str) -> List[str]:
    """Extract file path references."""
    files = _RE_FILE_REFS.findall(text)
    return list(set(files))[:20]


def _extract_api_endpoints(text: str) -> List[str]:
    """Extract API endpoints (paths starting with /)."""
    endpoints = _RE_API_PATHS.findall(text)
    api_endpoints = [e for e in endpoints if _RE_API_PREFIX.match(e)]
    return list(set(api_endpoints))[:10]


def _extract_questions(text: str) -> List[str]:
    """Extract questions."""
    questions = _RE_QUESTIONS.findall(text)
    return [q.strip() for q in questions if len(q.strip()) > 10][:10]


def _extract_risks(text: str) -> List[str]:
    """Extract risks."""
    risks = []
    for pattern in _RE_RISKS:
        risks.extend(pattern.findall(text))
    return [risk.strip() for risk in risks][:10]


def _extract_decisions(text: str) -> List[str]:
    """Extract decisions."""
    decisions = []
    for pattern in _RE_DECISIONS:
        decisions.extend(pattern.findall(text))
    return [dec.strip() for dec in decisions][:10]


def _extract_assumptions(text: str) -> List[str]:
    """Extract assumptions."""
    assumptions = []
    for pattern in _RE_ASSUMPTIONS:
        assumptions.extend(pattern.findall(text))
    return [assumption.strip() for assumption in assumptions][:10]


def _extract_constraints(text: str) -> List[str]:
    """Extract constraints."""
    constraints = []
    for pattern in _RE_CONSTRAINTS:
        constraints.extend(pattern.findall(text))
    return [constraint.strip() for constraint in constraints][:10]


def _empty_result() -> Dict[str, Any]:
    """Return empty result dict."""
    return {
        "doc.title": "",
        "doc.author": "",
        "doc.date": "",
        "doc.version": "",
        "doc.language": "",
        "doc.summary": "",
        "doc.key_concepts": [],
        "doc.technical_terms": [],
        "doc.acronyms": [],
        "doc.urls": [],
        "doc.code_snippets": [],
        "doc.key_requirements": [],
        "doc.entities": [],
        "doc.references": [],
        "doc.related_files": [],
        "doc.api_endpoints": [],
        "doc.open_questions": [],
        "doc.risks": [],
        "doc.decisions": [],
        "doc.assumptions": [],
        "doc.constraints": []
    }
