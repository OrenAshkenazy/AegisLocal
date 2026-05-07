# Contributing to AegisLocal

Thanks for your interest in contributing to AegisLocal.

## Reporting Bugs

Open a [Bug Report](https://github.com/OrenAshkenazy/AegisLocal/issues/new?template=bug_report.md)
issue and fill in the template. Include the output of `uv run python main.py scan`
(or the relevant command) and the Python version you are running.

## Suggesting Features

Open a [Feature Request](https://github.com/OrenAshkenazy/AegisLocal/issues/new?template=feature_request.md)
issue. Describe the problem you want to solve before proposing a solution.

## Submitting Changes

1. Fork the repository and create a branch from `main`.
2. Install dependencies: `uv sync --extra test`
3. Make your changes.
4. Run tests: `uv run --extra test pytest`
5. Run a compile check: `uv run python -m compileall core engines main.py`
6. Open a pull request against `main`.

### Code Style

- Follow the existing patterns in the codebase.
- Keep changes focused. One PR per logical change.
- Add tests for new functionality.

### Commit Sign-Off (DCO)

This project uses the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO). By submitting a pull request, you certify that you wrote or have the
right to submit the code under the project's Apache 2.0 license.

Sign off each commit with:

```
git commit -s -m "your commit message"
```

This adds a `Signed-off-by:` line to your commit. All commits in a PR must be
signed off.

## License

By contributing, you agree that your contributions will be licensed under the
Apache License 2.0.
