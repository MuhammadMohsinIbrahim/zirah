## What and why

<!-- What does this change, and why? Link the issue: "Closes #123". -->

## Type

- [ ] Bug fix
- [ ] New or changed detection rule
- [ ] False-positive fix
- [ ] Feature
- [ ] Docs, tests or tooling

## Checklist

- [ ] `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy core` and `uv run pytest` pass
- [ ] Tests cover the change (coverage stays at or above the 95% floor)
- [ ] For rules: a malicious fixture with `_zirah_expect`, benign look-alikes, and the rule pack `version` bumped
- [ ] For false-positive fixes: the reported text is now a benign fixture
- [ ] Fixtures are harmless: `example.invalid` hosts and `zirah_fake_...` secrets only
- [ ] Works with `--llm none` and no network
- [ ] CHANGELOG.md updated under **Unreleased** (if users would notice)
