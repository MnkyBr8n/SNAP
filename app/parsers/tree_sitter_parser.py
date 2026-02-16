"""
Tree-sitter AST parser for code structure extraction.

Supports 14 languages: Python, TypeScript, JavaScript, Java, Go, Rust, C++, C, C#,
Ruby, PHP, Swift, Kotlin, Scala.

Output format: Dict[str, Any] with field_id keys matching master_notebook.yaml
Authorization: Can only fill code.file.*, code.imports.*, code.exports.*, code.functions.*, code.classes.*
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, Optional, TYPE_CHECKING
import subprocess
import sys
import time

if TYPE_CHECKING:
    from tree_sitter import Language, Parser, Node

try:
    from tree_sitter import Language, Parser, Node
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

from app.logging.logger import get_logger
from app.security.snap_limits import SnapLimitsEnforcer

logger = get_logger("parsers.tree_sitter")

# Supported languages (tree-sitter v0.20+ API)
# Each language requires its own package: pip install tree-sitter-{language}
# Map: lang_key -> (module_name, language_attr)
LANGUAGE_MODULE_MAP = {
    "python": ("tree_sitter_python", "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "tsx": ("tree_sitter_typescript", "language_tsx"),
    "java": ("tree_sitter_java", "language"),
    "go": ("tree_sitter_go", "language"),
    "rust": ("tree_sitter_rust", "language"),
    "c": ("tree_sitter_c", "language"),
    "cpp": ("tree_sitter_cpp", "language"),
    "c_sharp": ("tree_sitter_c_sharp", "language"),
    "ruby": ("tree_sitter_ruby", "language"),
    "php": ("tree_sitter_php", "language_php"),
    "swift": ("tree_sitter_swift", "language"),
    "kotlin": ("tree_sitter_kotlin", "language"),
    "scala": ("tree_sitter_scala", "language"),
    "json": ("tree_sitter_json", "language"),
    "yaml": ("tree_sitter_yaml", "language"),
    "xml": ("tree_sitter_xml", "language_xml"),
}

SUPPORTED_LANGUAGES = list(LANGUAGE_MODULE_MAP.keys())

def _try_import_language(lang_key: str):
    """Import a tree-sitter language module. Auto-installs if missing."""
    if lang_key not in LANGUAGE_MODULE_MAP:
        raise ValueError(f"No grammar mapping for language key: {lang_key}")

    module_name, lang_attr = LANGUAGE_MODULE_MAP[lang_key]
    package_name = module_name.replace('_', '-')

    import importlib
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        logger.info(f"Auto-installing tree-sitter grammar: {package_name}...")
        install = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", package_name],
            capture_output=True,
            text=True,
            timeout=120,
            check=False
        )
        if install.returncode != 0:
            raise ImportError(
                f"Auto-install failed for {package_name} — "
                f"manual fix: pip install {package_name}\n"
                f"{install.stderr.strip()}"
            ) from exc
        try:
            module = importlib.import_module(module_name)
        except ImportError as e:
            raise ImportError(
                f"{package_name} installed but import still failed: {e}\n"
                f"Manual fix: pip install --upgrade {package_name}"
            ) from e

    lang = getattr(module, lang_attr, None)
    if lang is None:
        raise ImportError(f"Module {module_name} has no attribute '{lang_attr}'")
    return lang

# Parser instances cache (one per language)
_PARSERS: Dict[str, Any] = {}


def _get_parser(language: str) -> "Parser":
    """Get or create parser for language (tree-sitter v0.20+ API). Raises if unavailable."""
    if not TREE_SITTER_AVAILABLE:
        raise ImportError("py-tree-sitter not installed — tree-sitter is a required parser")

    lang_key = _map_language_to_grammar(language)
    if not lang_key:
        raise ValueError(f"No grammar mapping for language: {language}")

    if lang_key in _PARSERS:
        return _PARSERS[lang_key]

    # Raises ImportError if grammar package not installed
    lang_func = _try_import_language(lang_key)

    # New API: Language wraps the language function, Parser takes Language
    lang = Language(lang_func())
    parser = Parser(lang)
    _PARSERS[lang_key] = parser
    logger.info(f"Loaded tree-sitter grammar: {lang_key}")
    return parser


def _map_language_to_grammar(language: str) -> Optional[str]:
    """Map file extension or language name to grammar key."""
    mapping = {
        "py": "python",
        "python": "python",
        "ts": "typescript",
        "typescript": "typescript",
        "tsx": "tsx",
        "js": "javascript",
        "javascript": "javascript",
        "jsx": "javascript",
        "java": "java",
        "go": "go",
        "rs": "rust",
        "rust": "rust",
        "cpp": "cpp",
        "cc": "cpp",
        "cxx": "cpp",
        "c": "c",
        "cs": "c_sharp",
        "csharp": "c_sharp",
        "c#": "c_sharp",
        "c_sharp": "c_sharp",
        "rb": "ruby",
        "ruby": "ruby",
        "php": "php",
        "swift": "swift",
        "kt": "kotlin",
        "kotlin": "kotlin",
        "scala": "scala",
        "json": "json",
        "yaml": "yaml",
        "yml": "yaml",
        "xml": "xml"
    }
    return mapping.get(language.lower())


def parse_code_tree_sitter(
    path: Optional[Path] = None,
    content: Optional[str] = None,
    language: Optional[str] = None
) -> Dict[str, Any]:
    """
    Parse code file using tree-sitter AST analysis.
    
    Args:
        path: File path (if parsing from file)
        content: File content (if parsing from string, e.g., god parser shard)
        language: Language/extension (py, ts, js, etc.)
    
    Returns:
        Dict with field_id keys matching master_notebook_v2.yaml
        
    Raises:
        ImportError: if tree-sitter or required grammar is not installed
        RuntimeError: if parsing fails
        ValueError: if language cannot be determined
    """
    if not TREE_SITTER_AVAILABLE:
        raise ImportError("py-tree-sitter not installed")
    
    start_time = time.time()
    
    # Get content
    if content is None:
        if path is None:
            raise ValueError("Either path or content must be provided")
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        file_path = str(path)
    else:
        file_path = str(path) if path else "chunk"
    
    # Detect language
    if language is None:
        if path is None:
            raise ValueError("Language must be provided when parsing content string")
        language = path.suffix.lstrip('.')
    
    # Get parser — raises ImportError/ValueError if unavailable
    parser = _get_parser(language)
    
    # Parse
    try:
        tree = parser.parse(bytes(content, "utf8"))
        root = tree.root_node
    except Exception as e:
        raise RuntimeError(f"Tree-sitter parsing failed: {e}") from e
    
    # Extract based on language
    lang_key = _map_language_to_grammar(language)
    
    if lang_key == "python":
        result = _extract_python(root, content, file_path)
    elif lang_key in ("typescript", "tsx", "javascript"):
        result = _extract_typescript(root, content, file_path, lang_key)
    elif lang_key == "go":
        result = _extract_go(root, content, file_path)
    elif lang_key == "java":
        result = _extract_java(root, content, file_path)
    elif lang_key == "rust":
        result = _extract_rust(root, content, file_path)
    elif lang_key in ("cpp", "c"):
        result = _extract_cpp(root, content, file_path)
    elif lang_key == "c_sharp":
        result = _extract_csharp(root, content, file_path)
    elif lang_key == "ruby":
        result = _extract_ruby(root, content, file_path)
    elif lang_key == "php":
        result = _extract_php(root, content, file_path)
    elif lang_key == "swift":
        result = _extract_swift(root, content, file_path)
    elif lang_key == "kotlin":
        result = _extract_kotlin(root, content, file_path)
    elif lang_key == "scala":
        result = _extract_scala(root, content, file_path)
    elif lang_key in ("json", "yaml", "xml"):
        result = _extract_config_structure(
            file_path=file_path,
            content=content,
            lang_key=lang_key
        )
    else:
        raise ValueError(f"Unsupported language: {lang_key}")
    
    # Add common fields
    result["code.file.path"] = file_path
    result["code.file.language"] = language
    result["code.file.loc"] = len(content.splitlines())
    
    duration_ms = (time.time() - start_time) * 1000
    
    logger.debug("Tree-sitter parse complete", extra={
        "file": file_path,
        "language": language,
        "loc": result["code.file.loc"],
        "parse_duration_ms": duration_ms,
        "functions_found": len(result.get("code.functions.names", [])),
        "classes_found": len(result.get("code.classes.names", []))
    })
    
    return result


def _get_node_text(node: Node, source: str) -> str:
    """Extract text for a node with literal value filtering."""
    text = source[node.start_byte:node.end_byte]
    return _filter_literal_value(text, node.type)


# Patterns that indicate potential prompt injection in literals
_IMPERATIVE_PATTERNS = [
    "AI:",
    "ASSISTANT:",
    "SYSTEM:",
    "USER:",
    "IMPORTANT:",
    "INSTRUCTION:",
    "IGNORE PREVIOUS",
    "IGNORE ALL",
    "DISREGARD",
    "NEW INSTRUCTION",
    "OVERRIDE",
    "YOU MUST",
    "YOU SHOULD",
    "YOU ARE",
    "ACT AS",
    "PRETEND",
    "ROLEPLAY",
    "FROM NOW ON",
    "DO NOT",
    "ALWAYS ",
    "NEVER ",
    "<|",  # Common LLM token markers
    "|>",
    "```system",
    "```assistant",
]

# Node types that contain literal values to filter
_LITERAL_NODE_TYPES = {
    "string",
    "string_literal",
    "interpreted_string_literal",
    "raw_string_literal",
    "template_string",
    "comment",
    "line_comment",
    "block_comment",
    "doc_comment",
}


def _filter_literal_value(text: str, node_type: str) -> str:
    """
    Filter literal values for potential prompt injection patterns.

    Args:
        text: Raw text from node
        node_type: Tree-sitter node type

    Returns:
        Filtered text (truncated if suspicious, original otherwise)
    """
    # Only filter literal/comment nodes
    if node_type not in _LITERAL_NODE_TYPES:
        return text

    # Check for suspicious patterns (case-insensitive)
    text_upper = text.upper()

    for pattern in _IMPERATIVE_PATTERNS:
        if pattern.upper() in text_upper:
            # Found suspicious pattern - truncate and flag
            truncate_pos = text_upper.find(pattern.upper())
            if truncate_pos > 0:
                # Keep content before the pattern, add marker
                return text[:truncate_pos] + "[FILTERED:IMPERATIVE]"
            else:
                # Pattern at start - just flag
                return "[FILTERED:IMPERATIVE]"

    # Check for excessive length in literals (potential data exfil)
    if len(text) > 5000:
        return text[:500] + f"[TRUNCATED:{len(text)} chars]"

    return text


def _extract_python(root: Node, source: str, file_path: str) -> Dict[str, Any]:
    """Extract Python-specific fields."""
    result = {
        "code.imports.modules": [],
        "code.imports.from_files": [],
        "code.imports.external": [],
        "code.imports.internal": [],
        "code.exports.functions": [],
        "code.exports.classes": [],
        "code.functions.names": [],
        "code.functions.signatures": [],
        "code.functions.async": [],
        "code.functions.decorators": [],
        "code.classes.names": [],
        "code.classes.inheritance": [],
        "code.classes.methods": [],
    }
    
    def traverse(node: Node):
        # Import statements
        if node.type == "import_statement":
            for child in node.children:
                if child.type == "dotted_name":
                    module = _get_node_text(child, source)
                    result["code.imports.modules"].append(module)
                    # Heuristic: if '.' in module, likely external package
                    if '.' in module or module in ('os', 'sys', 'json', 'typing'):
                        result["code.imports.external"].append(module)
        
        elif node.type == "import_from_statement":
            module_name = None
            for child in node.children:
                if child.type == "dotted_name":
                    module_name = _get_node_text(child, source)
                    result["code.imports.modules"].append(module_name)
            if module_name:
                if module_name.startswith('.'):
                    result["code.imports.internal"].append(module_name)
                else:
                    result["code.imports.external"].append(module_name)
        
        # Function definitions
        elif node.type == "function_definition":
            func_name = None
            decorators = []
            is_async = False
            
            for child in node.children:
                if child.type == "identifier":
                    func_name = _get_node_text(child, source)
                elif child.type == "decorator":
                    dec_text = _get_node_text(child, source)
                    decorators.append({"decorator": dec_text, "line": child.start_point[0] + 1})
                elif child.type == "async":
                    is_async = True
            
            if func_name:
                result["code.functions.names"].append(func_name)
                
                # Get signature
                sig_text = _get_node_text(node.child_by_field_name("parameters") or node, source)
                result["code.functions.signatures"].append(f"def {func_name}{sig_text}")
                
                if is_async:
                    result["code.functions.async"].append(func_name)
                
                if decorators:
                    result["code.functions.decorators"].extend(decorators)
                
                # Top-level functions are exports
                if node.parent and node.parent.type == "module":
                    result["code.exports.functions"].append(func_name)
        
        # Class definitions
        elif node.type == "class_definition":
            class_name = None
            bases = []
            methods = []
            
            for child in node.children:
                if child.type == "identifier":
                    class_name = _get_node_text(child, source)
                elif child.type == "argument_list":
                    # Base classes
                    for arg in child.children:
                        if arg.type == "identifier":
                            bases.append(_get_node_text(arg, source))
                elif child.type == "block":
                    # Methods
                    for stmt in child.children:
                        if stmt.type == "function_definition":
                            for method_child in stmt.children:
                                if method_child.type == "identifier":
                                    methods.append(_get_node_text(method_child, source))
                                    break
            
            if class_name:
                result["code.classes.names"].append(class_name)
                if bases:
                    result["code.classes.inheritance"].extend(bases)
                if methods:
                    result["code.classes.methods"].extend(methods)
                
                # Top-level classes are exports
                if node.parent and node.parent.type == "module":
                    result["code.exports.classes"].append(class_name)
        
        # Recurse
        for child in node.children:
            traverse(child)
    
    traverse(root)
    
    # Deduplicate
    for key in result:
        if isinstance(result[key], list):
            result[key] = list(dict.fromkeys(result[key]))  # Preserve order, remove duplicates
    
    return result


def _extract_typescript(root: Node, source: str, file_path: str, lang_key: str) -> Dict[str, Any]:
    """Extract TypeScript/JavaScript fields."""
    result = {
        "code.imports.modules": [],
        "code.imports.from_files": [],
        "code.exports.functions": [],
        "code.exports.classes": [],
        "code.exports.constants": [],
        "code.exports.types": [],
        "code.functions.names": [],
        "code.functions.signatures": [],
        "code.functions.async": [],
        "code.classes.names": [],
        "code.classes.methods": [],
    }
    
    def traverse(node: Node):
        # Import statements
        if node.type == "import_statement":
            for child in node.children:
                if child.type == "string":
                    module = _get_node_text(child, source).strip('"\'')
                    result["code.imports.modules"].append(module)
                    if module.startswith('.'):
                        result["code.imports.from_files"].append(module)
        
        # Function declarations
        elif node.type in ("function_declaration", "function"):
            func_name = None
            is_async = False
            is_export = False
            
            # Check if exported
            if node.parent and "export" in node.parent.type:
                is_export = True
            
            for child in node.children:
                if child.type == "identifier":
                    func_name = _get_node_text(child, source)
                elif child.type == "async":
                    is_async = True
            
            if func_name:
                result["code.functions.names"].append(func_name)
                
                sig_node = node.child_by_field_name("parameters")
                if sig_node:
                    params = _get_node_text(sig_node, source)
                    result["code.functions.signatures"].append(f"function {func_name}{params}")
                
                if is_async:
                    result["code.functions.async"].append(func_name)
                
                if is_export:
                    result["code.exports.functions"].append(func_name)
        
        # Arrow functions (limited extraction)
        elif node.type == "arrow_function":
            if node.parent and node.parent.type == "variable_declarator":
                for child in node.parent.children:
                    if child.type == "identifier":
                        func_name = _get_node_text(child, source)
                        result["code.functions.names"].append(func_name)
                        break
        
        # Class declarations
        elif node.type == "class_declaration":
            class_name = None
            methods = []
            is_export = False
            
            if node.parent and "export" in node.parent.type:
                is_export = True
            
            for child in node.children:
                if child.type == "identifier" or child.type == "type_identifier":
                    class_name = _get_node_text(child, source)
                elif child.type == "class_body":
                    for method in child.children:
                        if method.type == "method_definition":
                            for method_child in method.children:
                                if method_child.type == "property_identifier":
                                    methods.append(_get_node_text(method_child, source))
                                    break
            
            if class_name:
                result["code.classes.names"].append(class_name)
                if methods:
                    result["code.classes.methods"].extend(methods)
                if is_export:
                    result["code.exports.classes"].append(class_name)
        
        # Type aliases (TypeScript)
        elif node.type == "type_alias_declaration":
            for child in node.children:
                if child.type == "type_identifier":
                    type_name = _get_node_text(child, source)
                    result["code.exports.types"].append(type_name)
                    break
        
        # Interface declarations (TypeScript)
        elif node.type == "interface_declaration":
            for child in node.children:
                if child.type == "type_identifier":
                    interface_name = _get_node_text(child, source)
                    result["code.exports.types"].append(interface_name)
                    break
        
        # Recurse
        for child in node.children:
            traverse(child)
    
    traverse(root)
    
    # Deduplicate
    for key in result:
        if isinstance(result[key], list):
            result[key] = list(dict.fromkeys(result[key]))
    
    return result


def _extract_go(root: Node, source: str, file_path: str) -> Dict[str, Any]:
    """Extract Go fields."""
    result = {
        "code.file.package": "",
        "code.imports.modules": [],
        "code.functions.names": [],
        "code.functions.signatures": [],
        "code.classes.names": [],  # Structs
        "code.classes.methods": [],
    }
    
    def traverse(node: Node):
        # Package declaration
        if node.type == "package_clause":
            for child in node.children:
                if child.type == "package_identifier":
                    result["code.file.package"] = _get_node_text(child, source)
        
        # Import declarations
        elif node.type == "import_spec":
            for child in node.children:
                if child.type == "interpreted_string_literal":
                    import_path = _get_node_text(child, source).strip('"')
                    result["code.imports.modules"].append(import_path)
        
        # Function declarations
        elif node.type == "function_declaration":
            func_name = None
            for child in node.children:
                if child.type == "identifier":
                    func_name = _get_node_text(child, source)
                    break
            
            if func_name:
                result["code.functions.names"].append(func_name)
                params = node.child_by_field_name("parameters")
                if params:
                    sig = f"func {func_name}{_get_node_text(params, source)}"
                    result["code.functions.signatures"].append(sig)
        
        # Method declarations
        elif node.type == "method_declaration":
            method_name = None
            receiver = None
            
            for child in node.children:
                if child.type == "field_identifier":
                    method_name = _get_node_text(child, source)
                elif child.type == "parameter_list" and receiver is None:
                    # First parameter list is receiver
                    receiver = _get_node_text(child, source)
            
            if method_name:
                result["code.classes.methods"].append(method_name)
        
        # Struct declarations
        elif node.type == "type_declaration":
            for child in node.children:
                if child.type == "type_spec":
                    for spec_child in child.children:
                        if spec_child.type == "type_identifier":
                            struct_name = _get_node_text(spec_child, source)
                            result["code.classes.names"].append(struct_name)
                            break
        
        # Recurse
        for child in node.children:
            traverse(child)
    
    traverse(root)
    
    for key in result:
        if isinstance(result[key], list):
            result[key] = list(dict.fromkeys(result[key]))
    
    return result


def _extract_java(root: Node, source: str, file_path: str) -> Dict[str, Any]:
    """Extract Java fields."""
    result = {
        "code.file.package": "",
        "code.imports.modules": [],
        "code.classes.names": [],
        "code.classes.inheritance": [],
        "code.classes.interfaces": [],
        "code.classes.methods": [],
        "code.functions.names": [],
    }
    
    def traverse(node: Node):
        # Package declaration
        if node.type == "package_declaration":
            for child in node.children:
                if child.type == "scoped_identifier":
                    result["code.file.package"] = _get_node_text(child, source)
        
        # Import declarations
        elif node.type == "import_declaration":
            for child in node.children:
                if child.type == "scoped_identifier":
                    result["code.imports.modules"].append(_get_node_text(child, source))
        
        # Class declarations
        elif node.type == "class_declaration":
            class_name = None
            superclass = None
            interfaces = []
            methods = []
            
            for child in node.children:
                if child.type == "identifier":
                    class_name = _get_node_text(child, source)
                elif child.type == "superclass":
                    for sc_child in child.children:
                        if sc_child.type == "type_identifier":
                            superclass = _get_node_text(sc_child, source)
                elif child.type == "super_interfaces":
                    for si_child in child.children:
                        if si_child.type == "type_identifier":
                            interfaces.append(_get_node_text(si_child, source))
                elif child.type == "class_body":
                    for method in child.children:
                        if method.type == "method_declaration":
                            for method_child in method.children:
                                if method_child.type == "identifier":
                                    methods.append(_get_node_text(method_child, source))
                                    break
            
            if class_name:
                result["code.classes.names"].append(class_name)
                if superclass:
                    result["code.classes.inheritance"].append(superclass)
                if interfaces:
                    result["code.classes.interfaces"].extend(interfaces)
                if methods:
                    result["code.classes.methods"].extend(methods)
                    result["code.functions.names"].extend(methods)
        
        # Recurse
        for child in node.children:
            traverse(child)
    
    traverse(root)
    
    for key in result:
        if isinstance(result[key], list):
            result[key] = list(dict.fromkeys(result[key]))
    
    return result


def _extract_rust(root: Node, source: str, file_path: str) -> Dict[str, Any]:
    """Extract Rust fields - basic implementation."""
    result = {
        "code.imports.modules": [],
        "code.functions.names": [],
        "code.classes.names": [],  # Structs/Enums
    }
    
    def traverse(node: Node):
        if node.type == "use_declaration":
            # Basic use statement extraction
            text = _get_node_text(node, source)
            result["code.imports.modules"].append(text)
        
        elif node.type == "function_item":
            for child in node.children:
                if child.type == "identifier":
                    result["code.functions.names"].append(_get_node_text(child, source))
                    break
        
        elif node.type in ("struct_item", "enum_item"):
            for child in node.children:
                if child.type == "type_identifier":
                    result["code.classes.names"].append(_get_node_text(child, source))
                    break
        
        for child in node.children:
            traverse(child)
    
    traverse(root)
    
    return result


def _extract_cpp(root: Node, source: str, file_path: str) -> Dict[str, Any]:
    """Extract C/C++ fields - basic implementation."""
    result = {
        "code.imports.modules": [],  # #include statements
        "code.functions.names": [],
        "code.classes.names": [],
    }
    
    def traverse(node: Node):
        if node.type == "preproc_include":
            text = _get_node_text(node, source)
            result["code.imports.modules"].append(text)
        
        elif node.type == "function_definition":
            declarator = node.child_by_field_name("declarator")
            if declarator:
                for child in declarator.children:
                    if child.type == "identifier":
                        result["code.functions.names"].append(_get_node_text(child, source))
                        break
        
        elif node.type == "class_specifier":
            for child in node.children:
                if child.type == "type_identifier":
                    result["code.classes.names"].append(_get_node_text(child, source))
                    break
        
        for child in node.children:
            traverse(child)
    
    traverse(root)
    
    return result


def _extract_csharp(root: Node, source: str, file_path: str) -> Dict[str, Any]:
    """Extract C# fields - basic implementation."""
    result = {
        "code.file.package": "",  # namespace
        "code.imports.modules": [],  # using statements
        "code.classes.names": [],
        "code.functions.names": [],
    }
    
    def traverse(node: Node):
        if node.type == "namespace_declaration":
            for child in node.children:
                if child.type == "identifier":
                    result["code.file.package"] = _get_node_text(child, source)
                    break
        
        elif node.type == "using_directive":
            for child in node.children:
                if child.type in ("identifier", "qualified_name"):
                    result["code.imports.modules"].append(_get_node_text(child, source))
        
        elif node.type == "class_declaration":
            for child in node.children:
                if child.type == "identifier":
                    result["code.classes.names"].append(_get_node_text(child, source))
                    break
        
        elif node.type == "method_declaration":
            for child in node.children:
                if child.type == "identifier":
                    result["code.functions.names"].append(_get_node_text(child, source))
                    break
        
        for child in node.children:
            traverse(child)
    
    traverse(root)
    
    return result


def _extract_ruby(root: Node, source: str, file_path: str) -> Dict[str, Any]:
    """Extract Ruby fields - basic implementation."""
    result = {
        "code.imports.modules": [],
        "code.functions.names": [],
        "code.classes.names": [],
        "code.classes.methods": [],
    }
    
    def traverse(node: Node):
        if node.type in ("call", "command") and node.child_count > 0:
            method_name = _get_node_text(node.children[0], source)
            if method_name in ("require", "require_relative"):
                for child in node.children:
                    if child.type == "string":
                        result["code.imports.modules"].append(_get_node_text(child, source))
        
        elif node.type == "method":
            for child in node.children:
                if child.type == "identifier":
                    result["code.functions.names"].append(_get_node_text(child, source))
                    break
        
        elif node.type == "class":
            for child in node.children:
                if child.type == "constant":
                    result["code.classes.names"].append(_get_node_text(child, source))
                    break
        
        for child in node.children:
            traverse(child)
    
    traverse(root)
    
    return result


def _extract_php(root: Node, source: str, file_path: str) -> Dict[str, Any]:
    """Extract PHP fields - basic implementation."""
    result = {
        "code.file.package": "",  # namespace
        "code.imports.modules": [],
        "code.functions.names": [],
        "code.classes.names": [],
    }
    
    def traverse(node: Node):
        if node.type == "namespace_definition":
            for child in node.children:
                if child.type == "namespace_name":
                    result["code.file.package"] = _get_node_text(child, source)
        
        elif node.type == "namespace_use_declaration":
            for child in node.children:
                if child.type == "namespace_name":
                    result["code.imports.modules"].append(_get_node_text(child, source))
        
        elif node.type == "function_definition":
            for child in node.children:
                if child.type == "name":
                    result["code.functions.names"].append(_get_node_text(child, source))
                    break
        
        elif node.type == "class_declaration":
            for child in node.children:
                if child.type == "name":
                    result["code.classes.names"].append(_get_node_text(child, source))
                    break
        
        for child in node.children:
            traverse(child)
    
    traverse(root)
    
    return result


def _extract_swift(root: Node, source: str, file_path: str) -> Dict[str, Any]:
    """Extract Swift fields - basic implementation."""
    result = {
        "code.imports.modules": [],
        "code.functions.names": [],
        "code.classes.names": [],
    }
    
    def traverse(node: Node):
        if node.type == "import_declaration":
            for child in node.children:
                if child.type == "identifier":
                    result["code.imports.modules"].append(_get_node_text(child, source))
        
        elif node.type == "function_declaration":
            for child in node.children:
                if child.type == "simple_identifier":
                    result["code.functions.names"].append(_get_node_text(child, source))
                    break
        
        elif node.type in ("class_declaration", "struct_declaration"):
            for child in node.children:
                if child.type == "type_identifier":
                    result["code.classes.names"].append(_get_node_text(child, source))
                    break
        
        for child in node.children:
            traverse(child)
    
    traverse(root)
    
    return result


def _extract_kotlin(root: Node, source: str, file_path: str) -> Dict[str, Any]:
    """Extract Kotlin fields - basic implementation."""
    result = {
        "code.file.package": "",
        "code.imports.modules": [],
        "code.functions.names": [],
        "code.classes.names": [],
    }
    
    def traverse(node: Node):
        if node.type == "package_header":
            for child in node.children:
                if child.type == "identifier":
                    result["code.file.package"] = _get_node_text(child, source)
        
        elif node.type == "import_header":
            for child in node.children:
                if child.type == "identifier":
                    result["code.imports.modules"].append(_get_node_text(child, source))
        
        elif node.type == "function_declaration":
            for child in node.children:
                if child.type == "simple_identifier":
                    result["code.functions.names"].append(_get_node_text(child, source))
                    break
        
        elif node.type == "class_declaration":
            for child in node.children:
                if child.type == "type_identifier":
                    result["code.classes.names"].append(_get_node_text(child, source))
                    break
        
        for child in node.children:
            traverse(child)
    
    traverse(root)
    
    return result


def _extract_scala(root: Node, source: str, file_path: str) -> Dict[str, Any]:
    """Extract Scala fields - basic implementation."""
    result = {
        "code.file.package": "",
        "code.imports.modules": [],
        "code.functions.names": [],
        "code.classes.names": [],
    }
    
    def traverse(node: Node):
        if node.type == "package_clause":
            for child in node.children:
                if child.type == "package_identifier":
                    result["code.file.package"] = _get_node_text(child, source)
        
        elif node.type == "import_declaration":
            text = _get_node_text(node, source)
            result["code.imports.modules"].append(text)
        
        elif node.type == "function_definition":
            for child in node.children:
                if child.type == "identifier":
                    result["code.functions.names"].append(_get_node_text(child, source))
                    break
        
        elif node.type in ("class_definition", "object_definition", "trait_definition"):
            for child in node.children:
                if child.type == "identifier":
                    result["code.classes.names"].append(_get_node_text(child, source))
                    break
        
        for child in node.children:
            traverse(child)
    
    traverse(root)
    
    return result


# Startup validation
def validate_tree_sitter_installation() -> None:
    """
    Validate tree-sitter installation on startup. Auto-installs core and grammars if missing.

    Raises:
        ImportError: if tree-sitter cannot be installed or validated after auto-install
    """
    if not TREE_SITTER_AVAILABLE:
        logger.info("tree-sitter core not found — auto-installing...")
        install = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--upgrade", "tree-sitter"],
            capture_output=True,
            text=True,
            timeout=120,
            check=False
        )
        if install.returncode != 0:
            raise ImportError(
                f"tree-sitter auto-install failed — manual fix: pip install tree-sitter\n"
                f"{install.stderr.strip()}"
            )
        raise ImportError(
            "tree-sitter installed — restart SNAP to complete initialization"
        )

    for lang_key in SUPPORTED_LANGUAGES:
        _get_parser(lang_key)  # auto-installs grammar if missing, raises if install fails
        logger.info(f"Tree-sitter grammar loaded: {lang_key}")

    logger.info(f"All {len(SUPPORTED_LANGUAGES)} tree-sitter grammars validated")


def _extract_config_structure(
    file_path: Path,
    content: str,
    lang_key: str
) -> Dict[str, Any]:
    """
    Extract structure and settings from config files.

    Args:
        file_path: Path to config file
        content: File contents
        lang_key: json, yaml, or xml

    Returns:
        Dict with config.* field_ids
    """
    import json
    import yaml
    import re
    import defusedxml.ElementTree as ET

    # Parse based on format — raises on malformed input
    if lang_key == "json":
        data = json.loads(content)
    elif lang_key in ("yaml", "yml"):
        data = yaml.safe_load(content)
    elif lang_key == "xml":
        root = ET.fromstring(content)
        data = _xml_to_dict(root)
    else:
        raise ValueError(f"Unsupported config format: {lang_key}")

    # Extract structure
    toplevel_keys = list(data.keys()) if isinstance(data, dict) else []
    nested_paths = _get_all_paths(data, prefix="")
    depth = _get_max_depth(data)
    parameter_names = _extract_parameter_names(nested_paths)

    # Extract environment variables
    env_vars = re.findall(r'\$\{([A-Z_][A-Z0-9_]*)\}', content)
    env_vars += re.findall(r'%([A-Z_][A-Z0-9_]*)%', content)
    env_vars = list(set(env_vars))

    # Extract database connections (look for common patterns)
    db_patterns = [
        r'(postgresql://[^\s"\']+)',
        r'(mysql://[^\s"\']+)',
        r'(mongodb://[^\s"\']+)',
        r'(redis://[^\s"\']+)'
    ]
    db_connections = []
    for pattern in db_patterns:
        matches = re.findall(pattern, content)
        # Redact secrets from connection strings
        for match in matches:
            redacted = re.sub(r':([^:@]+)@', ':***@', match)
            db_connections.append(redacted)

    # Extract API endpoints
    api_endpoints = re.findall(r'https?://[^\s"\']+/[^\s"\']*', content)
    api_hosts = list(set(
        re.findall(r'https?://([^/\s"\']+)', content)
    ))

    return {
        "config.file.path": str(file_path),
        "config.file.format": lang_key,
        "config.structure.toplevel_keys": toplevel_keys,
        "config.structure.nested_paths": nested_paths[:100],  # Limit to prevent bloat
        "config.structure.depth": depth,
        "config.settings.parameter_names": parameter_names[:100],
        "config.settings.env_vars": env_vars,
        "config.database.connection_strings": db_connections,
        "config.api.endpoints": api_endpoints[:50],
        "config.api.hosts": api_hosts[:20]
    }


def _xml_to_dict(element) -> dict:
    """Convert XML element to dict structure."""
    result = {}
    if element.attrib:
        result["@attributes"] = element.attrib
    if element.text and element.text.strip():
        if len(element) == 0:
            return element.text.strip()
        result["#text"] = element.text.strip()
    for child in element:
        child_data = _xml_to_dict(child)
        if child.tag in result:
            if not isinstance(result[child.tag], list):
                result[child.tag] = [result[child.tag]]
            result[child.tag].append(child_data)
        else:
            result[child.tag] = child_data
    return result or element.text


def _get_all_paths(data, prefix="") -> list:
    """Get all dot-notation paths in nested structure."""
    paths = []
    if isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else key
            paths.append(path)
            if isinstance(value, (dict, list)):
                paths.extend(_get_all_paths(value, path))
    elif isinstance(data, list):
        for idx, item in enumerate(data):
            path = f"{prefix}[{idx}]"
            if isinstance(item, (dict, list)):
                paths.extend(_get_all_paths(item, path))
    return paths


def _get_max_depth(data, current_depth=0) -> int:
    """Calculate maximum nesting depth."""
    if isinstance(data, dict):
        if not data:
            return current_depth
        return max(_get_max_depth(v, current_depth + 1) for v in data.values())
    elif isinstance(data, list):
        if not data:
            return current_depth
        return max(_get_max_depth(item, current_depth + 1) for item in data)
    return current_depth


def _extract_parameter_names(paths: list) -> list:
    """Extract leaf parameter names from paths."""
    params = []
    for path in paths:
        # Get last component (leaf name)
        parts = path.split('.')
        leaf = parts[-1]
        # Skip array indices
        if not leaf.startswith('['):
            params.append(leaf)
    return list(set(params))
