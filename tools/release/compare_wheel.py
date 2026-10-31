"""Compares a wheel built here with the wheel of the same version on the
Python Package Index, for a project whose version is already published.

    python tools/release/compare_wheel.py <the wheel built here>

Why: the framework packages have versions of their own, and a release of
the library publishes one only where its version is not yet on the index.
If its code was changed and its version not raised, that change would
silently never be published. So a release stops where the code differs.

What is compared: every file of the wheel outside its ".dist-info" folder,
byte for byte, and, from the METADATA file, the name, the version, the
Python versions it needs and the packages it needs. Not compared, because
they depend on the build tool's version and not on the code: the rest of
METADATA (the README among it), RECORD and WHEEL. So a change to a
README alone is not found.

The published wheel is read from the index's own list of files for that
version, and its SHA-256 is checked against the one the index gives
before it is opened. It uses only Python itself.
"""

import hashlib
import io
import json
import sys
import urllib.request
import zipfile
from email.parser import Parser

KEPT_FIELDS = ("Name", "Version", "Requires-Python", "Requires-Dist")


def stop(message):
    print(f"Stopped: {message}", file=sys.stderr)
    sys.exit(1)


def read(address):
    # Only https: the second address comes from the index's own answer.
    if not address.startswith("https://"):
        stop(f"the address {address!r} is not an https address, so it was not read.")
    # The two S310 notes are set aside: the line above allows https alone.
    request = urllib.request.Request(address, headers={"Accept": "application/json"})  # noqa: S310
    with urllib.request.urlopen(request, timeout=60) as answer:  # noqa: S310
        return answer.read()


def contents(data):
    """The files outside .dist-info, and the fields of METADATA that are compared."""
    files, metadata = {}, None
    with zipfile.ZipFile(io.BytesIO(data)) as wheel:
        for name in wheel.namelist():
            if name.endswith("/"):
                continue
            top = name.split("/", 1)[0]
            if top.endswith(".dist-info"):
                if name == f"{top}/METADATA":
                    if metadata is not None:
                        stop("the wheel holds two METADATA files.")
                    metadata = wheel.read(name).decode("utf-8")
                continue
            files[name] = hashlib.sha256(wheel.read(name)).hexdigest()
    if metadata is None:
        stop("the wheel holds no METADATA file.")
    message = Parser().parsestr(metadata, headersonly=True)
    fields = {field: sorted(message.get_all(field) or []) for field in KEPT_FIELDS}
    return files, fields


def main():
    if len(sys.argv) != 2:
        stop("give the path of the wheel built here.")
    with open(sys.argv[1], "rb") as handle:
        built = handle.read()
    built_files, built_fields = contents(built)
    if len(built_fields["Name"]) != 1 or len(built_fields["Version"]) != 1:
        stop("the wheel built here does not give one name and one version.")
    name, version = built_fields["Name"][0], built_fields["Version"][0]

    listing = json.loads(read(f"https://pypi.org/pypi/{name}/{version}/json"))
    wheels = [f for f in listing.get("urls", []) if f.get("packagetype") == "bdist_wheel"]
    if len(wheels) != 1:
        stop(f"{name} {version} has {len(wheels)} wheels on the Python Package Index; exactly one was expected.")
    published = read(wheels[0]["url"])
    if hashlib.sha256(published).hexdigest() != wheels[0]["digests"]["sha256"]:
        stop(f"the wheel downloaded for {name} {version} does not match the SHA-256 the index gives for it.")
    published_files, published_fields = contents(published)

    differences = []
    for path in sorted(set(built_files) | set(published_files)):
        if path not in published_files:
            differences.append(f"{path}: only in the wheel built here")
        elif path not in built_files:
            differences.append(f"{path}: only in the published wheel")
        elif built_files[path] != published_files[path]:
            differences.append(f"{path}: different")
    for field in KEPT_FIELDS:
        if built_fields[field] != published_fields[field]:
            differences.append(f"METADATA {field}: {built_fields[field]} here, {published_fields[field]} published")

    if differences:
        print(f"{name} {version} is already on the Python Package Index, but this commit's code for it differs:", file=sys.stderr)
        for line in differences:
            print(f"  {line}", file=sys.stderr)
        stop(f"raise the version of {name} in its pyproject.toml, or undo the change; then sign a new tag. Nothing has been published by this run.")
    print(f"{name} {version}: the code here is the same as the published wheel's ({len(built_files)} file{'' if len(built_files) == 1 else 's'} compared).")


if __name__ == "__main__":
    main()
