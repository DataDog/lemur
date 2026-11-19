"""
.. module: lemur.plugins.utils
    :platform: Unix

    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Kevin Glisson <kglisson@netflix.com>

"""

from copy import deepcopy

from lemur.plugins.base import plugins


def redact_plugin_options(slug, options):
    """Omit credentials using trusted plugin definitions, not stored metadata."""
    definitions = {option["name"]: option for option in plugins.get(slug).options}
    result = []
    for option in deepcopy(options or []):
        definition = definitions.get(option.get("name"), {})
        if definition.get("sensitive"):
            continue
        if "plugin" in definition.get("type", ""):
            for value_field in ("value", "default"):
                nested = option.get(value_field)
                if isinstance(nested, dict):
                    for field in ("plugin_options", "pluginOptions"):
                        if field in nested:
                            nested[field] = redact_plugin_options(nested["slug"], nested[field])
        result.append(option)
    return result


def get_plugin_option(name, options):
    """
    Retrieve option name from options dict.
    :param options:
    :return:
    """
    for o in options:
        if o.get("name") == name:
            return o.get("value", o.get("default"))


def set_plugin_option(name, value, options):
    """
    Set value for option name for options dict.
    :param options:
    """
    for o in options:
        if o.get("name") == name:
            o.update({"value": value})
