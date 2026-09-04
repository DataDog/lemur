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


def test_configure_logging_formats_third_party_root_log_once_as_json(capsys):
    import json
    import logging

    from flask import Flask

    from lemur.factory import configure_logging

    app = Flask("test_third_party_root_logging")
    app.config.update(LOG_FILE="/dev/stdout", LOG_JSON=True, LOG_LEVEL="INFO")
    root_logger = logging.getLogger()
    third_party_logger = logging.getLogger("third_party.test")
    original_root_handlers = root_logger.handlers[:]
    original_root_level = root_logger.level
    original_third_party_handlers = third_party_logger.handlers[:]
    original_third_party_level = third_party_logger.level
    original_third_party_propagate = third_party_logger.propagate

    try:
        root_logger.handlers.clear()
        third_party_logger.handlers.clear()
        third_party_logger.setLevel(logging.INFO)
        third_party_logger.propagate = True

        configure_logging(app)
        configure_logging(app)
        capsys.readouterr()

        third_party_logger.info("third-party message")

        output_lines = capsys.readouterr().out.strip().splitlines()
        assert len(output_lines) == 1
        record = json.loads(output_lines[0])
        assert record["message"] == "third-party message"
        assert record["levelname"] == "INFO"
    finally:
        configured_handlers = set(app.logger.handlers + root_logger.handlers)
        for handler in configured_handlers:
            handler.close()
        app.logger.handlers.clear()
        root_logger.handlers[:] = original_root_handlers
        root_logger.setLevel(original_root_level)
        third_party_logger.handlers[:] = original_third_party_handlers
        third_party_logger.setLevel(original_third_party_level)
        third_party_logger.propagate = original_third_party_propagate


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
