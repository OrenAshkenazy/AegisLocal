# Copyright 2026 Oren Ashkenazy
# SPDX-License-Identifier: Apache-2.0

from engines.model_inventory import discover_project_model_names


def test_discovers_model_names_from_env_files(tmp_path):
    backend = tmp_path / "backend"
    backend.mkdir()
    (backend / ".env").write_text(
        "\n".join(
            [
                "AI_MAIN_MODEL=groq/qwen/qwen3-32b",
                "AI_INSIGHT_MODEL='gemini/gemini-2.5-flash'",
                'AI_GUARD_MODEL="anthropic/claude-haiku-4-5-20251001"',
                "HUGGINGFACE_API_KEY=hf_secret",
                "LLM_RATE_LIMIT_MAX_RETRIES=2",
                "EMPTY_MODEL=",
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / ".env.example").write_text(
        "AI_MAIN_MODEL=example/ignored\n",
        encoding="utf-8",
    )
    worktree_env = tmp_path / ".worktrees" / "copy" / ".env"
    worktree_env.parent.mkdir(parents=True)
    worktree_env.write_text("AI_MAIN_MODEL=ignored/worktree\n", encoding="utf-8")

    assert discover_project_model_names(tmp_path) == [
        "groq/qwen/qwen3-32b",
        "gemini/gemini-2.5-flash",
        "anthropic/claude-haiku-4-5-20251001",
    ]
