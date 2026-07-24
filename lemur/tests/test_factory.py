def test_app_logger_propagates_to_root(app):
    assert app.logger.propagate is True
