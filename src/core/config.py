# Imports

from pathlib import Path
import yaml
from src.core.logger import logger

def config_loader(path: Path | str = '../../config/preprocessing/validation_shema.yaml'):
    """Loads the configuration file.

    Parameters:
        path (Path | str): Optional, path to configuration file.

    Returns:
        Configuration as a dict."""

    try:
        with open(path, 'r') as file:
            cfg = dict(yaml.safe_load(file))
    except FileNotFoundError as e:
        logger.exception("configuration file not found: %s", path)
        return None
    except yaml.YAMLError as e:
        logger.exception("Error loading the configuration file: %s", path)
        return None

    logger.info("Successfully loaded the configuration file: %s", path)
    return cfg