import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).parent.parent
SHA_PIN = re.compile(r"uses: [\w.-]+/[\w.-]+@[0-9a-f]{40} # v[\d.]+")


def pins(path):
    lines = (ROOT / path).read_text().splitlines()
    return dict(l.lower().split("==") for l in lines if "==" in l)


def workflow_files():
    return [ROOT / "action.yml", *(ROOT / ".github/workflows").glob("*.yml")]


def test_pyproject_pins_match_requirements():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    runtime = pins("requirements.txt")
    for dep in project["dependencies"]:
        name, version = dep.lower().split("==")
        assert runtime[name] == version, dep


def test_console_script_points_at_cli_main():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert project["scripts"]["dependency-compass"] == "dependency_compass.cli:main"


def test_build_backend_is_pinned():
    build = tomllib.loads((ROOT / "pyproject.toml").read_text())["build-system"]
    assert all("==" in r for r in build["requires"])


def test_third_party_actions_are_pinned_to_commit_sha():
    for path in workflow_files():
        for line in path.read_text().splitlines():
            line = line.strip().removeprefix("- ")
            if line.startswith("uses:") and not line.startswith("uses: ./"):
                assert SHA_PIN.fullmatch(line), f"{path.name}: {line}"


def test_action_inputs_never_interpolated_into_scripts():
    # ${{ inputs.x }} inside `run:` is a shell injection; env indirection isn't.
    text = (ROOT / "action.yml").read_text()
    for block in re.findall(r"run: \|\n((?:\s{8}.*\n?)+)", text):
        assert "${{" not in block


def test_workflows_use_read_only_permissions():
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    assert "permissions:\n  contents: read" in ci
    assert "persist-credentials: false" in ci
