import os

FIXTURES_DIR = os.path.join(os.path.dirname(__file__), "fixtures")


def fixture_path(*parts: str) -> str:
    return os.path.join(FIXTURES_DIR, *parts)
