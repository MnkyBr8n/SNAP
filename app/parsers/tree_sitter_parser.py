"""
Tree-sitter AST parser for code structure extraction.

languages: Python, TypeScript, JavaScript, Java, Go, Rust, C++, C, C#,
Ruby, PHP, Swift, Kotlin, Scala, Nim.

Output format: Dict[str, Any] with field_id keys matching master_notebook.yaml
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
    "python":     ("tree_sitter_python",     "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "tsx":        ("tree_sitter_typescript", "language_tsx"),
    "java":       ("tree_sitter_java",       "language"),
    "go":         ("tree_sitter_go",         "language"),
    "rust":       ("tree_sitter_rust",       "language"),
    "c":          ("tree_sitter_c",          "language"),
    "cpp":        ("tree_sitter_cpp",        "language"),
    "c_sharp":    ("tree_sitter_c_sharp",    "language"),
    "ruby":       ("tree_sitter_ruby",       "language"),
    "php":        ("tree_sitter_php",        "language_php"),
    "swift":      ("tree_sitter_swift",      "language"),
    "kotlin":     ("tree_sitter_kotlin",     "language"),
    "scala":      ("tree_sitter_scala",      "language"),
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
    }
    return mapping.get(language.lower())


def _base_code_result() -> Dict[str, Any]:
    """All code.* and repo.* field_ids with empty defaults. Every language gets these."""
    return {
        "code.file.path":                   "",
        "code.file.language":               "",
        "code.file.loc":                    "",
        "code.file.package":                "",
        "code.imports.modules":             [],
        "code.imports.from_files":          [],
        "code.imports.external":            [],
        "code.imports.internal":            [],
        "code.exports.functions":           [],
        "code.exports.classes":             [],
        "code.exports.constants":           [],
        "code.exports.types":               [],
        "code.functions.names":             [],
        "code.functions.signatures":        [],
        "code.functions.async":             [],
        "code.functions.decorators":        [],
        "code.content.bodies":              {},
        "code.content.constants":           {},
        "code.classes.names":               [],
        "code.classes.inheritance":         [],
        "code.classes.methods":             [],
        "code.classes.properties":          [],
        "code.classes.interfaces":          [],
        "code.classes.method_signatures":   [],
        "code.classes.decorators":          [],
        "code.classes.docstring":           [],
        "code.connections.depends_on":      [],
        "code.connections.depended_by":     [],
        "code.connections.function_calls":  [],
        "code.connections.instantiates":    [],
    }


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

        Raises:
        ImportError: if tree-sitter or required grammar is not installed
        RuntimeError: if parsing fails
        ValueError: if language cannot be determined
    """
    if not TREE_SITTER_AVAILABLE:
        raise ImportError("py-tree-sitter not installed")

    logger.info(f"[TREE_SITTER] START: {path}")
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
        content_bytes = bytes(content, "utf8")
        tree = parser.parse(content_bytes)
        root = tree.root_node
    except Exception as e:
        raise RuntimeError(f"Tree-sitter parsing failed: {e}") from e

    # Extract based on language
    lang_key = _map_language_to_grammar(language)

    if lang_key == "python":
        result = _extract_python(root, content_bytes, file_path)
    elif lang_key in _LANG_CFG:
        result = _extract_generic(root, content_bytes, lang_key)
    else:
        raise ValueError(f"Unsupported language: {lang_key}")

   
    base = _base_code_result()
    base.update(result)
    base["code.file.path"] = file_path
    base["code.file.language"] = language
    base["code.file.loc"] = len(content.splitlines())
    if base["code.imports.modules"] and not base["code.connections.depends_on"]:
        base["code.connections.depends_on"] = list(base["code.imports.modules"])
    result = base
    
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


def _get_node_text(node: Node, source: bytes) -> str:
    """Extract text for a node using byte offsets (tree-sitter uses UTF-8 byte positions)."""
    text = source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
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


def _extract_python(root: Node, source: bytes, file_path: str) -> Dict[str, Any]:
    """Extract Python-specific fields."""
    result = {
        "code.file.path":[],
        "code.file.language": [],
        "code.file.loc": [],
        "code.file.package": [],
        "code.imports.modules": [],
        "code.imports.from_files": [],
        "code.imports.external": [],
        "code.imports.internal": [],
        "code.exports.functions": [],
        "code.exports.classes": [],
        "code.exports.constants": [],
        "code.exports.types": [],
        "code.functions.names": [],
        "code.functions.signatures": [],
        "code.functions.async": [],
        "code.functions.decorators": [],
        "code.content.bodies": {},
        "code.content.constants": {},
        "code.classes.names": [],
        "code.classes.inheritance": [],
        "code.classes.methods": [],
        "code.classes.properties": [],
        "code.classes.decorators": [],
        "code.classes.method_signatures": [],
        "code.classes.docstring": [],
        "code.classes.interfaces": [],
        
    }
    
    def traverse(node: Node):
        if node.type == "import_statement":
            for child in node.children:
                if child.type == "dotted_name":
                    module = _get_node_text(child, source)
                    result["code.imports.modules"].append(module)
                    if '.' in module or module in ('os', 'sys', 'json', 'typing'):
                        result["code.imports.external"].append(module)
        
        elif node.type == "import_from_statement":
            module_name = None
            is_relative = False
            for child in node.children:
                if child.type == "relative_import":
                    is_relative = True
                    for rc in child.children:
                        if rc.type == "dotted_name":
                            module_name = _get_node_text(rc, source)
                elif child.type == "dotted_name" and module_name is None:
                    module_name = _get_node_text(child, source)
            if module_name:
                result["code.imports.modules"].append(module_name)
            if is_relative:
                entry = module_name or "."
                result["code.imports.internal"].append(entry)
                result["code.imports.from_files"].append(entry)
            elif module_name:
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
                
                # Extract function body
                body_node = node.child_by_field_name("body")
                if body_node:
                    result["code.content.bodies"][func_name] = _get_node_text(body_node, source)
                
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
            method_sigs = []
            decorators = []
            properties = []
            docstring = ""

            for child in node.children:
                if child.type == "identifier":
                    class_name = _get_node_text(child, source)
                elif child.type == "decorator":
                    decorators.append(_get_node_text(child, source))
                elif child.type == "argument_list":
                    for arg in child.children:
                        if arg.type == "identifier":
                            bases.append(_get_node_text(arg, source))
                elif child.type == "block":
                    for stmt in child.children:
                        if stmt.type == "expression_statement" and not docstring:
                            for expr in stmt.children:
                                if expr.type in ("string", "concatenated_string"):
                                    raw = _get_node_text(expr, source).strip("\"' \t\n")
                                    docstring = raw.split("\n")[0].strip()[:200]
                                    break
                        elif stmt.type == "function_definition":
                            method_name = None
                            for method_child in stmt.children:
                                if method_child.type == "identifier":
                                    method_name = _get_node_text(method_child, source)
                                    methods.append(method_name)
                                    break
                            if method_name:
                                params_node = stmt.child_by_field_name("parameters")
                                return_node = stmt.child_by_field_name("return_type")
                                if params_node:
                                    sig = f"{method_name}{_get_node_text(params_node, source)}"
                                    if return_node:
                                        sig += f" -> {_get_node_text(return_node, source)}"
                                    method_sigs.append(sig)
                            if method_name == "__init__":
                                body_node = stmt.child_by_field_name("body")
                                if body_node:
                                    for body_stmt in body_node.children:
                                        if body_stmt.type == "expression_statement":
                                            for assign in body_stmt.children:
                                                if assign.type == "assignment":
                                                    left = assign.child_by_field_name("left")
                                                    if left and left.type == "attribute":
                                                        obj = left.child_by_field_name("object")
                                                        attr = left.child_by_field_name("attribute")
                                                        if obj and _get_node_text(obj, source) == "self" and attr:
                                                            properties.append(_get_node_text(attr, source))

            if class_name:
                result["code.classes.names"].append(class_name)
                if bases:
                    result["code.classes.inheritance"].extend(bases)
                if methods:
                    result["code.classes.methods"].extend(methods)
                if method_sigs:
                    result["code.classes.method_signatures"].extend(method_sigs)
                if decorators:
                    result["code.classes.decorators"].extend(decorators)
                if properties:
                    result["code.classes.properties"].extend(properties)
                if docstring:
                    result["code.classes.docstring"].append(f"{class_name}: {docstring}")

                # Top-level classes are exports
                if node.parent and node.parent.type == "module":
                    result["code.exports.classes"].append(class_name)
        
        # Module-level constants
        elif node.type == "expression_statement":
            if node.parent and node.parent.type == "module":
                for child in node.children:
                    if child.type == "assignment":
                        name_node = child.child_by_field_name("left")
                        value_node = child.child_by_field_name("right")
                        if name_node and name_node.type == "identifier" and value_node:
                            result["code.content.constants"][_get_node_text(name_node, source)] = _get_node_text(value_node, source)

        # Recurse
        for child in node.children:
            traverse(child)
    
    traverse(root)
    
    # Deduplicate
    for key in result:
        if isinstance(result[key], list):
            result[key] = list(dict.fromkeys(result[key]))  # Preserve order, remove duplicates
    
    return result


# =============================================================================
# Unified config table + single generic extractor for all non-Python languages
# =============================================================================
# Each entry: package, imports, functions, async_kw, classes, class_body,
#             method_in_body, inheritance, interfaces, plus language-specific flags
_LANG_CFG: Dict[str, Dict] = {
    "javascript": dict(
        package=None,
        imports=[("import_statement", "string", "\"'`")],
        functions=[("function_declaration", "identifier"), ("function", "identifier")],
        async_kw="async",
        classes=[("class_declaration", ("identifier", "type_identifier"))],
        class_body="class_body", method_in_body=("method_definition", "property_identifier"),
        inheritance=("extends_clause", ("identifier", "type_identifier")),
    ),
    "typescript": dict(
        package=None,
        imports=[("import_statement", "string", "\"'`")],
        functions=[("function_declaration", "identifier"), ("function", "identifier")],
        async_kw="async",
        classes=[("class_declaration", ("identifier", "type_identifier"))],
        class_body="class_body", method_in_body=("method_definition", "property_identifier"),
        inheritance=("extends_clause", ("identifier", "type_identifier")),
        interfaces=[("interface_declaration", "type_identifier")],
        exports_types=[("type_alias_declaration", "type_identifier"), ("interface_declaration", "type_identifier")],
    ),
    "tsx": dict(
        package=None,
        imports=[("import_statement", "string", "\"'`")],
        functions=[("function_declaration", "identifier"), ("function", "identifier")],
        async_kw="async",
        classes=[("class_declaration", ("identifier", "type_identifier"))],
        class_body="class_body", method_in_body=("method_definition", "property_identifier"),
        inheritance=("extends_clause", ("identifier", "type_identifier")),
    ),
    "go": dict(
        package=("package_clause", "package_identifier"),
        imports=[("import_spec", "interpreted_string_literal", '"')],
        functions=[("function_declaration", "identifier")],
        async_kw=None,
        classes=[], class_body=None, method_in_body=None, inheritance=None,
        go_struct=("type_declaration", "type_spec", "type_identifier"),
        go_method=("method_declaration", "field_identifier"),
    ),
    "java": dict(
        package=("package_declaration", ("scoped_identifier", "identifier")),
        imports=[("import_declaration", ("scoped_identifier", "identifier"), None)],
        functions=[], async_kw=None,
        classes=[("class_declaration", "identifier"), ("interface_declaration", "type_identifier"), ("enum_declaration", "identifier")],
        class_body="class_body", method_in_body=("method_declaration", "identifier"),
        inheritance=("superclass", "type_identifier"),
        interfaces=[("super_interfaces", "type_identifier")],
    ),
    "rust": dict(
        package=None,
        imports=[("use_declaration", None, None)],
        functions=[("function_item", "identifier")],
        async_kw=None,
        classes=[("struct_item", "type_identifier"), ("enum_item", "type_identifier"), ("trait_item", "type_identifier")],
        class_body=None, method_in_body=None, inheritance=None,
        impl_body=("impl_item", "function_item", "identifier"),
    ),
    "c": dict(
        package=None,
        imports=[("preproc_include", None, None)],
        functions=[], async_kw=None,
        classes=[("struct_specifier", "type_identifier")],
        class_body=None, method_in_body=None, inheritance=None,
        func_via_declarator=True,
    ),
    "cpp": dict(
        package=None,
        imports=[("preproc_include", None, None)],
        functions=[], async_kw=None,
        classes=[("class_specifier", "type_identifier"), ("struct_specifier", "type_identifier")],
        class_body="body", method_in_body=("function_definition", "identifier"),
        inheritance=("base_class_clause", "type_identifier"),
        func_via_declarator=True,
    ),
    "c_sharp": dict(
        package=("namespace_declaration", ("identifier", "qualified_name")),
        imports=[("using_directive", ("identifier", "qualified_name"), None)],
        functions=[("method_declaration", "identifier")],
        async_kw=None,
        classes=[("class_declaration", "identifier"), ("struct_declaration", "identifier"), ("record_declaration", "identifier")],
        class_body="declaration_list", method_in_body=("method_declaration", "identifier"),
        inheritance=("base_list", ("identifier", "generic_name")),
        interfaces=[("interface_declaration", "identifier")],
    ),
    "ruby": dict(
        package=None, imports=[], functions=[("method", "identifier")],
        async_kw=None,
        classes=[("class", "constant")],
        class_body="body", method_in_body=("method", "identifier"),
        inheritance=("superclass", "constant"),
        ruby_require=True,
    ),
    "php": dict(
        package=("namespace_definition", "namespace_name"),
        imports=[("namespace_use_declaration", "namespace_name", None)],
        functions=[("function_definition", "name")],
        async_kw=None,
        classes=[("class_declaration", "name")],
        class_body="declaration_list", method_in_body=("method_declaration", "name"),
        inheritance=("base_clause", "qualified_name"),
    ),
    "swift": dict(
        package=None,
        imports=[("import_declaration", ("identifier", "access_path"), None)],
        functions=[("function_declaration", "simple_identifier")],
        async_kw="async",
        classes=[("class_declaration", "type_identifier"), ("struct_declaration", "type_identifier"), ("enum_declaration", "type_identifier")],
        class_body="class_body", method_in_body=("function_declaration", "simple_identifier"),
        inheritance=("type_inheritance_clause", "type_identifier"),
        interfaces=[("protocol_declaration", "type_identifier")],
    ),
    "kotlin": dict(
        package=("package_header", "identifier"),
        imports=[("import_header", "identifier", None)],
        functions=[("function_declaration", "simple_identifier")],
        async_kw=None,
        classes=[("class_declaration", "type_identifier")],
        class_body="class_body", method_in_body=("function_declaration", "simple_identifier"),
        inheritance=("delegation_specifiers", "type_identifier"),
    ),
    "scala": dict(
        package=("package_clause", ("package_identifier", "identifier")),
        imports=[("import_declaration", None, None)],
        functions=[("function_definition", "identifier")],
        async_kw=None,
        classes=[("class_definition", "identifier"), ("object_definition", "identifier"), ("trait_definition", "identifier")],
        class_body="template_body", method_in_body=("function_definition", "identifier"),
        inheritance=("extends_clause", ("type_identifier", "identifier")),
    ),
}


def _find_child_text(node: "Node", source: bytes, child_types) -> Optional[str]:
    if isinstance(child_types, str):
        child_types = (child_types,)
    for c in node.children:
        if c.type in child_types:
            return _get_node_text(c, source)
    return None


def _extract_generic(root: "Node", source: bytes, lang_key: str) -> Dict[str, Any]:
    """Single traversal for all non-Python languages, driven by _LANG_CFG."""
    cfg = _LANG_CFG[lang_key]
    r: Dict[str, Any] = {
        "code.file.package": "",
        "code.imports.modules": [], "code.imports.from_files": [],
        "code.imports.external": [], "code.imports.internal": [],
        "code.exports.functions": [], "code.exports.classes": [],
        "code.exports.types": [],
        "code.functions.names": [], "code.functions.signatures": [], "code.functions.async": [],
        "code.classes.names": [], "code.classes.methods": [],
        "code.classes.inheritance": [], "code.classes.interfaces": [],
        "code.connections.function_calls": [],
    }

    pkg_cfg      = cfg.get("package")
    imp_cfgs     = cfg.get("imports", [])
    fn_cfgs      = cfg.get("functions", [])
    cls_cfgs     = cfg.get("classes", [])
    async_kw     = cfg.get("async_kw")
    body_type    = cfg.get("class_body")
    method_cfg   = cfg.get("method_in_body")
    inherit_cfg  = cfg.get("inheritance")
    iface_cfgs   = cfg.get("interfaces", [])
    exp_types    = cfg.get("exports_types", [])
    go_struct    = cfg.get("go_struct")
    go_method    = cfg.get("go_method")
    impl_body    = cfg.get("impl_body")
    func_via_decl = cfg.get("func_via_declarator", False)
    ruby_req     = cfg.get("ruby_require", False)

    imp_types = {i[0] for i in imp_cfgs}
    fn_types  = {f[0] for f in fn_cfgs}
    cls_types = {c[0] for c in cls_cfgs}

    def _get_body(node: "Node") -> Optional["Node"]:
        if not body_type:
            return None
        b = node.child_by_field_name(body_type)
        return b or next((c for c in node.children if c.type == body_type), None)

    def traverse(node: "Node"):
        t = node.type

        if pkg_cfg and t == pkg_cfg[0]:
            name = _find_child_text(node, source, pkg_cfg[1])
            if name:
                r["code.file.package"] = name

        elif t in imp_types:
            for imp_t, name_child, strip in imp_cfgs:
                if t == imp_t:
                    if name_child is None:
                        text = _get_node_text(node, source)
                        for pfx in ("use ", "#include ", "import "):
                            if text.startswith(pfx):
                                text = text[len(pfx):]
                        r["code.imports.modules"].append(text.strip().rstrip(";"))
                    else:
                        name = _find_child_text(node, source, name_child)
                        if name:
                            if strip:
                                name = name.strip(strip)
                            r["code.imports.modules"].append(name)
                            if name.startswith("."):
                                r["code.imports.from_files"].append(name)
                                r["code.imports.internal"].append(name)
                            else:
                                r["code.imports.external"].append(name)

        elif ruby_req and t in ("call", "command") and node.child_count > 0:
            mname = _get_node_text(node.children[0], source)
            if mname in ("require", "require_relative"):
                mod = _find_child_text(node, source, "string")
                if mod:
                    mod = mod.strip("\"'")
                    r["code.imports.modules"].append(mod)
                    if mname == "require_relative":
                        r["code.imports.from_files"].append(mod)
                        r["code.imports.internal"].append(mod)

            for fn_t, name_child in fn_cfgs:
                if t == fn_t:
                    name = _find_child_text(node, source, name_child)
                    if name:
                        name = name.rstrip("*")
                        r["code.functions.names"].append(name)
                        if async_kw and any(c.type == async_kw for c in node.children):
                            r["code.functions.async"].append(name)
                        params = node.child_by_field_name("parameters") or node.child_by_field_name("params")
                        if params:
                            r["code.functions.signatures"].append(f"{name}{_get_node_text(params, source)}")
                        if t in ("proc_declaration", "func_declaration") and _get_node_text(
                                next((c for c in node.children if c.type == "identifier"), node), source
                        ).endswith("*"):
                            r["code.exports.functions"].append(name)

        elif func_via_decl and t == "function_definition":
            decl = node.child_by_field_name("declarator")
            if decl:
                name = _find_child_text(decl, source, "identifier")
                if name:
                    r["code.functions.names"].append(name)

        elif t in cls_types:
            for cls_t, name_child in cls_cfgs:
                if t == cls_t:
                    name = _find_child_text(node, source, name_child)
                    if name:
                        r["code.classes.names"].append(name)
                        body = _get_body(node)
                        if body and method_cfg:
                            mt, mn_type = method_cfg
                            for member in body.children:
                                if member.type == mt:
                                    mname = _find_child_text(member, source, mn_type)
                                    if mname:
                                        r["code.classes.methods"].append(mname)
                                        r["code.functions.names"].append(mname)
                        if inherit_cfg:
                            ih = next((c for c in node.children if c.type == inherit_cfg[0]), None)
                            if ih:
                                parent = _find_child_text(ih, source, inherit_cfg[1])
                                if parent:
                                    r["code.classes.inheritance"].append(parent)
                        for iface_t, iface_name_t in iface_cfgs:
                            for c in node.children:
                                if c.type == iface_t:
                                    iname = _find_child_text(c, source, iface_name_t)
                                    if iname:
                                        r["code.classes.interfaces"].append(iname)

        elif go_struct and t == "type_declaration":
            for c in node.children:
                if c.type == "type_spec":
                    name = _find_child_text(c, source, go_struct[2])
                    if name:
                        r["code.classes.names"].append(name)

        elif go_method and t == go_method[0]:
            name = _find_child_text(node, source, go_method[1])
            if name:
                r["code.classes.methods"].append(name)

        elif impl_body and t == impl_body[0]:
            body = node.child_by_field_name("body")
            if body:
                for c in body.children:
                    if c.type == impl_body[1]:
                        name = _find_child_text(c, source, impl_body[2])
                        if name:
                            r["code.classes.methods"].append(name)


        elif exp_types:
            for et, nt in exp_types:
                if t == et:
                    name = _find_child_text(node, source, nt)
                    if name:
                        r["code.exports.types"].append(name)

        for c in node.children:
            traverse(c)

    traverse(root)
    for k, v in r.items():
        if isinstance(v, list):
            r[k] = list(dict.fromkeys(v))
    return r


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
