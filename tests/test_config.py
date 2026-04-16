import os
import pytest
from unittest.mock import patch


def test_config_loads_required_vars():
    env = {
        "ANTHROPIC_API_KEY": "sk-ant-test",
        "GOOGLE_SHEETS_CREDS_JSON": "/tmp/creds.json",
        "AUDIT_SHEET_ID": "sheet123",
    }
    with patch.dict(os.environ, env, clear=True):
        import importlib
        import config as cfg_module
        importlib.reload(cfg_module)
        from config import Config
        c = Config()
        assert c.anthropic_api_key == "sk-ant-test"
        assert c.max_concurrent_agents == 5  # default


def test_config_raises_on_missing_key():
    with patch.dict(os.environ, {}, clear=True):
        import importlib
        import config as cfg_module
        importlib.reload(cfg_module)
        from config import Config
        with pytest.raises(EnvironmentError, match="ANTHROPIC_API_KEY"):
            Config()
