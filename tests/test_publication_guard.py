"""Exercise publication boundaries using isolated repositories and fake credentials."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
POLICY = ".public-repo-policy.json"
PYTHONPATH = str(PROJECT / "src")


def synthetic_credential() -> str:
    # Construct provider-shaped test data at runtime; do not store token fixtures.
    return "gh" + "p_" + "A" * 36


class PublicationGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = dict(
            os.environ,
            PYTHONPATH=PYTHONPATH,
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_CONFIG_NOSYSTEM="1",
            GIT_AUTHOR_NAME="Guard Test",
            GIT_AUTHOR_EMAIL="test@example.invalid",
            GIT_COMMITTER_NAME="Guard Test",
            GIT_COMMITTER_EMAIL="test@example.invalid",
        )
        self.git("init", "-q", "-b", "main")
        self.approve("README.md")
        self.write("README.md", "Public project documentation.\n")
        self.git("add", POLICY, "README.md")

    def git(self, *args: str, input_text: str | None = None) -> str:
        result = subprocess.run(
            ["git", *args],
            cwd=self.root,
            env=self.env,
            input=input_text,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, "Git test setup failed")
        return result.stdout.strip()

    def write(self, name: str, content: str | bytes) -> None:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)

    def approve(self, *paths: str) -> None:
        self.write(POLICY, json.dumps({"version": 1, "public_paths": [POLICY, *paths]}) + "\n")

    def run_cli(
        self, *args: str, input_text: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "guardrails", *args],
            cwd=self.root,
            env=self.env,
            input=input_text,
            text=True,
            capture_output=True,
        )

    def assert_blocked(
        self, result: subprocess.CompletedProcess[str], category: str | None = None
    ) -> None:
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(synthetic_credential(), result.stdout + result.stderr)
        if category:
            self.assertIn(category, result.stderr)

    def commit(self, message: str = "Public documentation") -> str:
        return self.git(
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            message,
        )

    def test_clean_staged_snapshot(self) -> None:
        self.assertEqual(self.run_cli("check", "--staged").returncode, 0)

    def test_forced_environment_file(self) -> None:
        self.write(".gitignore", ".env\n")
        self.write(".env", "CONFIGURATION=private\n")
        self.git("add", "-f", ".env")
        self.assert_blocked(self.run_cli("check", "--staged"), "environment-file")

    def test_database_is_prohibited_even_when_policy_approves_it(self) -> None:
        self.approve("README.md", "stores.sqlite")
        self.write("stores.sqlite", "Store information\n")
        self.git("add", POLICY, "stores.sqlite")
        self.assert_blocked(self.run_cli("check", "--staged"), "prohibited path")

    def test_unknown_path(self) -> None:
        self.write("stores.json", '{"stores": []}\n')
        self.git("add", "stores.json")
        self.assert_blocked(self.run_cli("check", "--staged"), "path-not-approved")

    def test_staged_secret_cannot_be_hidden_by_clean_worktree(self) -> None:
        self.write("README.md", synthetic_credential() + "\n")
        self.git("add", "README.md")
        self.write("README.md", "Clean working tree content.\n")
        self.assert_blocked(self.run_cli("check", "--staged"), "github-token")

    def test_unstaged_content_does_not_change_staged_scan(self) -> None:
        self.write("README.md", synthetic_credential() + "\n")
        self.assertEqual(self.run_cli("check", "--staged").returncode, 0)

    def test_staged_policy_cannot_be_replaced_by_worktree_policy(self) -> None:
        self.write("notes.md", "Not approved in the index.\n")
        self.git("add", "notes.md")
        self.approve("README.md", "notes.md")
        self.assert_blocked(self.run_cli("check", "--staged"), "path-not-approved")

    def test_unstaged_policy_cannot_expand_published_policy(self) -> None:
        self.write("notes.md", "Not approved by the published policy.\n")
        self.git("add", "notes.md")
        self.commit()
        self.approve("README.md", "notes.md")
        self.assert_blocked(self.run_cli("check", "--history", "HEAD"), "path-not-approved")
        head = self.git("rev-parse", "HEAD")
        hook_input = f"refs/heads/main {head} refs/heads/main {'0' * 40}\n"
        self.assert_blocked(
            self.run_cli("hook", "pre-push", input_text=hook_input), "path-not-approved"
        )

    def test_history_uses_committed_policy_even_if_worktree_policy_is_missing(self) -> None:
        self.commit()
        (self.root / POLICY).unlink()
        self.assertEqual(self.run_cli("check", "--history", "HEAD").returncode, 0)

    def test_deleted_historical_secret_is_blocked(self) -> None:
        self.write("README.md", synthetic_credential() + "\n")
        self.git("add", "README.md")
        self.commit()
        self.write("README.md", "Secret removed.\n")
        self.git("add", "README.md")
        self.commit()
        self.assertEqual(self.run_cli("check", "--staged").returncode, 0)
        self.assert_blocked(self.run_cli("check", "--history", "HEAD"), "github-token")

    def test_unknown_file_deleted_from_history_is_blocked(self) -> None:
        self.write("stores.json", '{"stores": []}\n')
        self.git("add", "stores.json")
        self.commit()
        self.git("rm", "-q", "stores.json")
        self.commit()
        self.assert_blocked(self.run_cli("check", "--history"), "path-not-approved")

    def test_first_push_checks_history(self) -> None:
        self.write("README.md", synthetic_credential() + "\n")
        self.git("add", "README.md")
        self.commit()
        head = self.git("rev-parse", "HEAD")
        hook_input = f"refs/heads/main {head} refs/heads/main {'0' * 40}\n"
        self.assert_blocked(self.run_cli("hook", "pre-push", input_text=hook_input), "github-token")

    def test_annotated_tag_messages_are_scanned(self) -> None:
        self.commit()
        self.git("-c", "tag.gpgsign=false", "tag", "-a", "release", "-m", synthetic_credential())
        self.assert_blocked(self.run_cli("check", "--history", "release"), "github-token")

    def test_commit_messages_are_scanned(self) -> None:
        self.commit(synthetic_credential())
        self.assert_blocked(self.run_cli("check", "--history", "HEAD"), "github-token")

    def test_commit_and_tag_headers_are_scanned(self) -> None:
        self.env["GIT_AUTHOR_NAME"] = synthetic_credential()
        self.commit()
        self.assert_blocked(self.run_cli("check", "--history", "HEAD"), "github-token")
        self.env["GIT_COMMITTER_NAME"] = synthetic_credential()
        self.git("-c", "tag.gpgsign=false", "tag", "-a", "release", "-m", "Public release")
        result = self.run_cli("check", "--history", "release")
        self.assert_blocked(result, "<tag-metadata-and-message>")

    def test_lightweight_tag_and_clean_history_pass(self) -> None:
        self.commit()
        self.git("tag", "release")
        self.assertEqual(self.run_cli("check", "--history", "release").returncode, 0)

    def test_tag_pointing_at_blob_is_rejected(self) -> None:
        self.commit()
        blob = self.git("rev-parse", "HEAD:README.md")
        self.git("tag", "blob-release", blob)
        self.assert_blocked(
            self.run_cli("check", "--history", "blob-release"),
            "standalone trees or blobs",
        )

    def test_invalid_push_input_fails_closed(self) -> None:
        self.assert_blocked(
            self.run_cli("hook", "pre-push", input_text="not hook input\n"), "Malformed"
        )

    def test_credentials_in_filenames_are_redacted(self) -> None:
        filename = synthetic_credential() + ".md"
        self.write(filename, "Unexpected file.\n")
        self.git("add", filename)
        result = self.run_cli("check", "--staged")
        self.assert_blocked(result, "redacted-path-")

    def test_credentials_in_push_and_history_ref_names_are_blocked(self) -> None:
        self.commit()
        head = self.git("rev-parse", "HEAD")
        ref = "refs/heads/" + synthetic_credential()
        self.git("update-ref", ref, head)
        self.assert_blocked(self.run_cli("check", "--history"), "reference name")
        hook_input = f"refs/heads/main {head} {ref} {'0' * 40}\n"
        self.assert_blocked(
            self.run_cli("hook", "pre-push", input_text=hook_input), "reference name"
        )

    def test_deletion_push_is_permitted(self) -> None:
        hook_input = f"(delete) {'0' * 40} refs/heads/old {'a' * 40}\n"
        self.assertEqual(self.run_cli("hook", "pre-push", input_text=hook_input).returncode, 0)

    def test_symlink_is_rejected(self) -> None:
        (self.root / "README.md").unlink()
        (self.root / "README.md").symlink_to("outside.md")
        self.git("add", "README.md")
        self.assert_blocked(self.run_cli("check", "--staged"), "symlink-submodule-or-special-file")

    def test_large_and_binary_content_are_rejected(self) -> None:
        for content, category in [
            (b"A" * (256 * 1024 + 1), "oversized-file"),
            (b"binary\x00content", "binary-file"),
        ]:
            with self.subTest(category=category):
                self.write("README.md", content)
                self.git("add", "README.md")
                self.assert_blocked(self.run_cli("check", "--staged"), category)

    def test_generic_credentials_and_placeholders(self) -> None:
        key_name = "SERVICE_" + "PASSWORD"
        for value, expected in [("YOUR_PASSWORD", 0), ("", 0), ("some-real-looking-value", 1)]:
            with self.subTest(expected=expected, empty=not value):
                self.write("README.md", key_name + '="' + value + '"\n')
                self.git("add", "README.md")
                result = self.run_cli("check", "--staged")
                self.assertEqual(result.returncode, expected)
                if expected:
                    self.assertNotIn(value, result.stderr)

    def test_unquoted_yaml_and_environment_credentials(self) -> None:
        for name, delimiter in [("settings.yaml", ": "), (".env.example", "=")]:
            for value in ["ordinary-value", "punctuation!+", "with-brackets[]"]:
                with self.subTest(name=name, delimiter=delimiter):
                    self.approve("README.md", name)
                    self.write(name, "PASS" + "WORD" + delimiter + value + "\n")
                    self.git("add", POLICY, name)
                    result = self.run_cli("check", "--staged")
                    self.assert_blocked(result, "hardcoded-credential")
                    self.assertNotIn(value, result.stderr)

    def test_actions_credential_reference_is_allowed(self) -> None:
        self.approve("README.md", "settings.yaml")
        self.write("settings.yaml", "SERVICE_" + "TOKEN: ${{ secrets.SERVICE_CREDENTIAL }}\n")
        self.git("add", POLICY, "settings.yaml")
        self.assertEqual(self.run_cli("check", "--staged").returncode, 0)

    def test_workflow_job_mapping_is_not_a_credential_value(self) -> None:
        self.approve("README.md", "settings.yaml")
        self.write(
            "settings.yaml",
            "jobs:\n  secret-scan:\n    name: Secret scan\n    runs-on: ubuntu-latest\n",
        )
        self.git("add", POLICY, "settings.yaml")
        self.assertEqual(self.run_cli("check", "--staged").returncode, 0)

    def test_secret_scanner_ignore_file_cannot_be_approved(self) -> None:
        self.approve("README.md", ".gitleaksignore")
        self.git("add", POLICY)
        self.assert_blocked(self.run_cli("check", "--staged"), "prohibited path")

    def test_hook_installer_preserves_existing_hooks_path(self) -> None:
        self.git("config", "--local", "core.hooksPath", "existing-custom-hooks")
        result = self.run_cli("setup", "apply", "--hooks-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.git("config", "--local", "core.hooksPath"), "existing-custom-hooks")

    def test_hook_installer_preserves_existing_default_hooks(self) -> None:
        self.write(".git/hooks/pre-commit", "#!/bin/sh\nexit 0\n")
        (self.root / ".git/hooks/pre-commit").chmod(0o755)
        result = self.run_cli("setup", "apply", "--hooks-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("existing executable default Git hooks", result.stderr)

    def test_installed_hook_blocks_commit(self) -> None:
        env = dict(self.env, GUARDRAILS_DEV_SRC=PYTHONPATH)
        result = subprocess.run(
            [sys.executable, "-m", "guardrails", "setup", "apply", "--hooks-only"],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.write("README.md", synthetic_credential() + "\n")
        self.git("add", "README.md")
        result = subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "commit", "-qm", "Blocked"],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assert_blocked(result, "github-token")


if __name__ == "__main__":
    unittest.main()
