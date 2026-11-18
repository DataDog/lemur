import socket

import logmatic


def json_log_formatter():
    """Build the JSON formatter shared by all Lemur process loggers."""
    return logmatic.JsonFormatter(extra={"hostname": socket.gethostname()})
