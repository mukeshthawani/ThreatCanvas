from threatcanvas.config import config
from mem0 import MemoryClient
from typing import List, Dict

mem0 = MemoryClient(api_key=config.MEM0_API_KEY)

def retrieve_context(query: str, user_id: str) -> List[Dict]:
    """Retrieve relevant context from Mem0"""

    memories = mem0.search(query, user_id=user_id)
    seralized_memories = ' '.join([mem["memory"] for mem in memories])
    context = [
        {
            "role": "system", 
            "content": f"Previous relevant log details: {seralized_memories}"
        },
        {
            "role": "user",
            "content": f"current logs information:{query}"
        }
    ]
    return context

def save_interaction(user_id: str, user_input: str, assistant_response: str):
    """Save the interaction to Mem0"""
    interaction = [
        {
          "role": "user",
          "content": user_input
        },
        {
            "role": "assistant",
            "content": assistant_response
        }
    ]
    mem0.add(interaction, user_id=user_id)