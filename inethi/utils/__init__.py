import logging
logger = logging.getLogger(__name__)


def log_utils_test():
    logger.debug("This is an info log from utils.__init__.")
    logger.error("This is an error log from utils.__init__.")
