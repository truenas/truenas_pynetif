# Coding Style

- Write minimal comments - only for complex logic or non-obvious decisions
- Prefer self-documenting code with clear variable and function names
- Avoid redundant comments that simply describe what the code does
- No comments for simple operations, getters, or setters
- Do not remove code comments that are already present
- Always use absolute imports even for the same package. Do not use relative imports.
- Do not import `Dict`, `List`, `Set`, `Union`, `Optional` from `typing` module, use type literals instead.
- Use `from __future__ import annotations` everywhere and don't use string annotations
