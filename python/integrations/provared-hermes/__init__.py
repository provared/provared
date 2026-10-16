# The entry Hermes loads when the plugin is installed as a folder
# ("hermes plugins install provared"). The code is in src/provared_hermes,
# which is also the package "provared-hermes" on the Python Package Index;
# Hermes installs what it needs ("provared") from pyproject.toml beside this
# file.
from .src.provared_hermes import register  # noqa: F401
