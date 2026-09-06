"""Version-1 public path policy parsing."""

from __future__ import annotations

import json

from guardrails.content import MAX_BYTES, path_categories
from guardrails.errors import GuardError

POLICY_PATH = ".public-repo-policy.json"


def load_policy(raw: bytes) -> set[str]:
    if len(raw) > MAX_BYTES:
        raise GuardError("Public policy exceeds size limit")
    try:
        policy = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as error:
        raise GuardError("Public policy is not valid UTF-8 JSON") from error
    if (
        not isinstance(policy, dict)
        or set(policy) != {"version", "public_paths"}
        or type(policy["version"]) is not int
        or policy["version"] != 1
        or not isinstance(policy["public_paths"], list)
        or not all(isinstance(path, str) and path for path in policy["public_paths"])
    ):
        raise GuardError("Public policy must contain version 1 and an exact public_paths list")
    paths = policy["public_paths"]
    if len(paths) != len(set(paths)) or POLICY_PATH not in paths:
        raise GuardError("Public policy has duplicate paths or does not approve itself")
    for path in paths:
        if any(char in path for char in "*?[") or path_categories(path, "100644", set(paths)):
            raise GuardError("Public policy contains an unsafe or prohibited path")
    return set(paths)
