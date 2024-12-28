from langchain_openai import AzureChatOpenAI
from threatcanvas.config import Configure
from threatcanvas.client import LLMClient
from langchain.agents.agent_types import AgentType
from langchain_experimental.agents import create_pandas_dataframe_agent
import pandas as pd

def get_response(df, verbose=False, agent_type=AgentType.OPENAI_FUNCTIONS, allow_dangerous_code=True, handle_parsing_errors=True):
    """Create a pandas DataFrame agent for the given DataFrame.

    Args:
        df (pandas.DataFrame): The DataFrame to create an agent for
        verbose (bool): Whether to print debug information
        agent_type (AgentType): The type of agent to create
        allow_dangerous_code (bool): Whether to allow dangerous code execution
        handle_parsing_errors (bool): Whether to handle parsing errors

    Returns:
        Agent: The pandas DataFrame agent for the given DataFrame
    """
    # Create LLM client and get the LLM instance
    client = LLMClient.create()
    llm = client.get_llm()

    agent = create_pandas_dataframe_agent(
        llm=llm,
        df=df,
        verbose=verbose,
        agent_type=agent_type,
        allow_dangerous_code=allow_dangerous_code,
        handle_parsing_errors=handle_parsing_errors
    )
    return agent

if __name__ == "__main__":
    df = pd.read_csv("data/Linux.csv")
    agent = get_response(df, verbose=True)
    print(agent.run("how many rows are in the data?"))