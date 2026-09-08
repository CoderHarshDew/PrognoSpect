# Imports

import logging
from pathlib import Path

# Log path
log_path = Path('logs/log.log')

if log_path.exists() and not log_path.is_file():
    log_path.rmdir()

log_path.parent.mkdir(parents=True, exist_ok=True)

# Setup Logger
logging.basicConfig(
    filename=log_path,
    filemode="a",
    encoding='utf-8',
    format="%(asctime)s || %(levelname)s || %(filename)s || %(lineno)s || %(message)s"
)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)