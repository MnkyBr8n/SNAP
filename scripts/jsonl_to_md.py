#!/usr/bin/env python3
"""Convert Claude conversation JSONL to markdown."""

import json
import sys
from pathlib import Path
from datetime import datetime

def jsonl_to_markdown(jsonl_path: Path) -> str:
    """Convert JSONL conversation log to markdown."""
    lines = []
    lines.append("# Claude Conversation: SNAP Binary Format & Nim Integration")
    lines.append(f"\n**Exported:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"\n**Source:** {jsonl_path.name}\n")
    lines.append("---\n")

    with open(jsonl_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            try:
                data = json.loads(line.strip())

                # Only process user and assistant messages
                if data.get('type') not in ('user', 'assistant'):
                    continue

                msg = data.get('message', {})
                role = msg.get('role')
                content = msg.get('content', [])

                if not role or not content:
                    continue

                # Format based on role
                if role == 'user':
                    lines.append("## 🧑 User\n")
                elif role == 'assistant':
                    lines.append("## 🤖 Assistant\n")
                else:
                    continue

                # Extract text content
                for item in content:
                    if isinstance(item, dict):
                        item_type = item.get('type')

                        if item_type == 'text':
                            text = item.get('text', '')
                            if text and not text.startswith('<ide_opened_file>'):
                                lines.append(f"{text}\n")

                        elif item_type == 'thinking':
                            # Include thinking blocks
                            thinking = item.get('thinking', '')
                            if thinking:
                                lines.append(f"<details>\n<summary>💭 Thinking</summary>\n\n{thinking}\n</details>\n")

                        elif item_type == 'tool_use':
                            tool_name = item.get('name', 'unknown')
                            lines.append(f"**🔧 Tool:** `{tool_name}`\n")

                        elif item_type == 'tool_result':
                            # Skip tool results for brevity
                            pass

                lines.append("\n---\n")

            except json.JSONDecodeError:
                continue
            except Exception as e:
                print(f"Error on line {line_num}: {e}", file=sys.stderr)
                continue

    return '\n'.join(lines)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python jsonl_to_md.py <input.jsonl> [output.md]")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else input_path.with_suffix('.md')

    if not input_path.exists():
        print(f"Error: {input_path} not found")
        sys.exit(1)

    markdown = jsonl_to_markdown(input_path)

    output_path.write_text(markdown, encoding='utf-8')
    print(f"Converted {input_path} -> {output_path}")
    print(f"Size: {len(markdown):,} bytes")
