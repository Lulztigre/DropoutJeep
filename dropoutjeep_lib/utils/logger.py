import logging

logger = logging.getLogger("dropoutjeep")

handler = logging.FileHandler("dropoutjeep.log")
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)
