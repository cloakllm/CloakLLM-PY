# Contributing to CloakLLM (Python)

Thanks for your interest in contributing! This guide will help you get started.

## Development Setup

```bash
git clone https://github.com/cloakllm/cloakllm.git
cd cloakllm
pip install -e ".[dev,litellm]"
python -m spacy download en_core_web_sm
```

## Running Tests

```bash
python -m pytest
```

All 35 tests should pass. Python 3.10+ is required.

## Project Structure

```
cloakllm/
  __init__.py        # Public API and exports
  __main__.py        # CLI entry point (scan/verify/stats)
  detector.py        # PII detection engine (spaCy NER + regex)
  tokenizer.py       # Deterministic tokenizer with reversible tokens
  shield.py          # Shield engine (detection + tokenization + audit)
  audit.py           # Hash-chained tamper-evident audit logger
  config.py          # Configuration and defaults
  integrations/      # LiteLLM middleware
tests/
  *.py               # Test files (pytest)
examples/
  *.py               # Usage examples
```

## Making Changes

1. Fork the repo and create a feature branch from `main`.
2. Make your changes in `cloakllm/`.
3. Add or update tests in `tests/` for any new behavior.
4. Run `python -m pytest` and ensure all tests pass.
5. Update `README.md` if you changed public API or behavior.
6. Open a pull request with a clear description of the change.

## Code Style

- Use type hints on all public functions.
- Follow PEP 8 conventions.
- Keep the core dependency surface minimal (spaCy only).
- Use `logging` instead of `print()` for debug output.
- Follow existing naming conventions (snake_case for functions, UPPER_SNAKE for constants).

## Reporting Issues

Open an issue at [github.com/cloakllm/cloakllm/issues](https://github.com/cloakllm/cloakllm/issues) with:

- A clear description of the problem or suggestion.
- Steps to reproduce (if reporting a bug).
- Your Python version (`python --version`) and OS.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
