from threatcanvas.config import config
from mem0 import MemoryClient

mem0 = MemoryClient(api_key=config.MEM0_API_KEY)
mem0.add()