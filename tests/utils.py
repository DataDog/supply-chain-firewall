"""
Common verifier testing utilities.
"""

from pathlib import Path

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package, LocalPackageSource, RemotePackageSource


def build_registry_package(ecosystem: ECOSYSTEM, package_name: str, package_version: str) -> Package:
    """
    Return a `Package` with the given parameters and the ecosystem's main registry as
    its artifact source.
    """
    match ecosystem:
        case ECOSYSTEM.Npm:
            source_url = _build_npm_tarball_url(package_name, package_version)
        case ECOSYSTEM.PyPI:
            source_url = _build_pypi_whl_url(package_name, package_version)

    return Package(
        ecosystem,
        package_name,
        package_version,
        RemotePackageSource(source_url),
    )


def build_remote_non_registry_package(ecosystem: ECOSYSTEM, package_name: str, package_version: str) -> Package:
    """
    Return a `Package` with the given parameters and a `RemotePackageSource` different
    from the ecosystems' main registry.
    """
    return Package(ecosystem, package_name, package_version, RemotePackageSource("https://example.com"))


def build_local_package(ecosystem: ECOSYSTEM, package_name: str, package_version: str) -> Package:
    """
    Return a `Package` with the given parameters and a local package artifact source.
    """
    return Package(
        ecosystem,
        package_name,
        package_version,
        LocalPackageSource(Path(f"/tmp/{package_name}_v{package_version}")),
    )


def _build_npm_tarball_url(package_name: str, package_version: str) -> str:
    """
    Return the npm URL for the package tarball specified by the given name and version.
    """
    unscoped_name = package_name.split("/")[-1]
    return f"https://registry.npmjs.org/{package_name}/-/{unscoped_name}-{package_version}.tgz"


def _build_pypi_whl_url(package_name: str, package_version: str) -> str:
    """
    Return a URL resembling that of the PyPI wheel file for the given package and version.
    """
    return (
        "https://files.pythonhosted.org/packages/00/00/"
        "000000000000000000000000000000000000000000000000000000000000/"
        f"{package_name}-{package_version}-py3-none-any.whl"
    )
