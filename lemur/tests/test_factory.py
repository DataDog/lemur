def test_app_logger_does_not_propagate_to_root(app):
    assert app.logger.propagate is False
