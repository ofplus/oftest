'''Docstring to silence pylint; ignores --ignore option for __init__.py'''
import sys

# Global config dictionary
# Populated by oft.
config = {}

# Global DataPlane instance used by all tests.
# Populated by oft.
dataplane_instance = None

# Alias of10 modules into oftest namespace for backwards compatbility
import of13
from of13 import *
for modname in of13.__all__:
    sys.modules["oftest." + modname] = sys.modules["of13." + modname]
