from threatcanvas.config import Configure
from langchain_openai import AzureChatOpenAI

class LLMClient:
    """Client for interacting with Azure OpenAI's chat completion API.

    This class provides a wrapper around Azure OpenAI's chat completion API,
    handling the configuration and communication with the service.

    Attributes:
        bot: Azure OpenAI client instance configured with deployment settings
    """

    def __init__(self):
        """Initialize the LLMClient with Azure OpenAI configuration settings."""
        config = Configure()

        self.bot = AzureChatOpenAI(
            azure_deployment=config.AZURE_DEPLOYMENT,
            azure_endpoint=config.AZURE_ENDPOINT,
            api_key=config.AZURE_API_KEY,
            api_version=config.AZURE_API_VERSION,
        )

    @classmethod
    def create(cls):
        """Factory method to create a new LLMClient instance.

        Returns:
            LLMClient: A configured instance of the LLM client
        """
        return cls()

    def get_llm(self):
        """Get the configured LLM instance.

        Returns:
            AzureChatOpenAI: The configured Azure OpenAI client
        """
        return self.bot

    def get_response(self, prompt: str) -> str:
        """Generate a response using the Azure OpenAI chat completion API.

        Args:
            prompt (str): The user's input prompt

        Returns:
            str: The generated response from the AI model
        """
        response = self.bot.invoke(prompt)
        print(response)
        return response