"""Fabric discovers serving endpoints, independently of certificate distribution."""

from lemur.plugins.bases import SourcePlugin


class FabricSourcePlugin(SourcePlugin):
    title = "Fabric"
    slug = "fabric-source"
    description = "Discovers certificates served by Envoy endpoints in a datacenter."
    author = "DataDog"
    author_url = "https://github.com/DataDog/lemur"

    options = [
        {
            "name": "datacenter",
            "type": "str",
            "required": True,
            "validation": r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$",
            "helpMessage": "Fabric datacenter, for example us1.staging.dog.",
        },
    ]

    def get_certificates(self, options, **kwargs):
        # Certificates are imported by existing sources. Fabric only observes usage.
        return []

    def get_endpoints(self, options, **kwargs):
        # Endpoint identity requires the persisted source, supplied by source sync.
        raise RuntimeError("Fabric endpoints must be discovered through source sync")
