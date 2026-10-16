import os

import uvicorn

from masqai.app import app_from_file
from masqai.config import load_config


app = app_from_file(os.getenv("MASQAI_CONFIG", "masqai.json"))

if __name__ == "__main__":
    config = load_config(os.getenv("MASQAI_CONFIG", "masqai.json"))
    if config.host != "127.0.0.1":
        raise ValueError("The unauthenticated MVP must bind to 127.0.0.1")
    uvicorn.run(app, host=config.host, port=config.port)
