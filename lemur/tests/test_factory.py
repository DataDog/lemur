def test_app_logger_does_not_propagate_to_root(app):
    assert app.logger.propagate is False


def test_configure_logging_is_idempotent_for_json_stdout():
    import logmatic
    from flask import Flask
    from logging import StreamHandler

    from lemur.factory import configure_logging

    app = Flask("test_json_stdout_logging")
    app.config.update(LOG_FILE="/dev/stdout", LOG_JSON=True, LOG_LEVEL="INFO")

    configure_logging(app)
    configure_logging(app)

    assert len(app.logger.handlers) == 1
    assert isinstance(app.logger.handlers[0], StreamHandler)
    assert isinstance(app.logger.handlers[0].formatter, logmatic.JsonFormatter)
    assert app.logger.propagate is False


def test_configure_logging_closes_replaced_character_device_handler():
    from flask import Flask
    from logging import FileHandler

    from lemur.factory import configure_logging

    app = Flask("test_character_device_logging")
    app.config.update(LOG_FILE="/dev/null", LOG_JSON=False, LOG_LEVEL="INFO")

    configure_logging(app)
    replaced_handler = app.logger.handlers[0]
    configure_logging(app)

    assert isinstance(app.logger.handlers[0], FileHandler)
    assert replaced_handler.stream is None


def test_json_log_formatter_returns_logmatic_formatter():
    import logmatic
    from lemur.factory import json_log_formatter

    assert isinstance(json_log_formatter(), logmatic.JsonFormatter)
