"""Copy canonical configuration defaults into built wheels without source duplicates."""
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py


class BuildWithDefaults(build_py):
    def run(self):
        super().run()
        root = Path(__file__).parent
        destination = Path(self.build_lib) / "maestro" / "resources" / "configs"
        destination.mkdir(parents=True, exist_ok=True)
        for source in (root / "configs").glob("*.yaml"):
            self.copy_file(str(source), str(destination / source.name))


setup(cmdclass={"build_py": BuildWithDefaults})
