"""
Common verifier testing utilities.
"""

from scfw.ecosystem import ECOSYSTEM
from scfw.package import Package, RemotePackageSource


def build_registry_sourced_package(
    ecosystem: ECOSYSTEM,
    package_name: str,
    package_version: str
) -> Package:
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


def _build_npm_tarball_url(package_name: str, package_version: str) -> str:
    """
    Return the npm URL for the package tarball specified by the given name and version.
    """
    unscoped_name = package_name.split("/")[-1]
    return f"https://registry.npmjs.org/{package_name}/-/{unscoped_name}-{package_version}.tgz"


def _build_pypi_whl_url(package_name: str, package_version: str) -> str:
    """
    Return the PyPI URL for the package wheel file specified by the given name and version.
    """
    return f"https://files.pythonhosted.org/packages/c3/20/748e38b466e0819491f0ce6e90ebe4184966ee304fe483e2c414b0f4ef07/{package_name}-{package_version}-py3-none-any.whl"
