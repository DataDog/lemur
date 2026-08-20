def test_app_logger_propagates_to_root(app):
    assert app.logger.propagate is True


def test_json_log_formatter_returns_logmatic_formatter():
    import logmatic
    from lemur.factory import json_log_formatter

    assert isinstance(json_log_formatter(), logmatic.JsonFormatter)
