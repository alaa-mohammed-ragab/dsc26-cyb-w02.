"""Command line: python -m tmcheck MODEL.yaml

Print one JSON object with the keys "issues", "gaps", "policy" and "ranked".
Exit code 2 if the file cannot be loaded, 1 if there are findings,
otherwise 0.
"""

import sys
import json
from dataclasses import asdict

from .core import (
    ModelError,
    load_model,
    validate,
    coverage_gaps,
    policy_findings,
    rank,
)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    if len(argv) != 1:
        print("usage: python -m tmcheck MODEL.yaml", file=sys.stderr)
        return 2

    path = argv[0]

    try:
        model = load_model(path)
    except ModelError as error:
        print(json.dumps({"error": str(error)}))
        return 2

    issues = validate(model)

    if issues:
        gaps = []
        policy = []
        ranked = rank(model)
    else:
        gaps = coverage_gaps(model)
        policy = policy_findings(model)
        ranked = rank(model)

    result = {
        "issues": [asdict(item) for item in issues],
        "gaps": [asdict(item) for item in gaps],
        "policy": [asdict(item) for item in policy],
        "ranked": [asdict(item) for item in ranked],
    }

    print(json.dumps(result, indent=2))

    if issues or gaps or policy:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())