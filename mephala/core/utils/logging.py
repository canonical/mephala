import logging
def configure(level="INFO"):
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(levelname)s %(name)s - %(message)s"
    )
