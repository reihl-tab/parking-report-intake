"""Checks requirements-test.txt's pins are satisfiable by what's actually
installed - stdlib only, no cryptography/Pillow import needed itself."""
import re
import unittest
from importlib import metadata


def _parse(path):
    pins = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"([A-Za-z0-9_.-]+)>=([0-9.]+),<([0-9.]+)", line)
            assert m, f"unparseable pin line: {line!r}"
            pins[m.group(1)] = (tuple(int(x) for x in m.group(2).split(".")),
                                 tuple(int(x) for x in m.group(3).split(".")))
    return pins


class TestRequirementsPins(unittest.TestCase):
    def test_pins_are_installed_and_in_bounds(self):
        pins = _parse("requirements-test.txt")
        self.assertEqual(set(pins), {"cryptography", "Pillow"})
        for name, (low, high) in pins.items():
            installed = tuple(int(x) for x in metadata.version(name).split(".")[:len(low)])
            self.assertGreaterEqual(installed, low, f"{name} below pinned floor")
            self.assertLess(installed, high, f"{name} at/above pinned ceiling")


if __name__ == "__main__":
    unittest.main()
