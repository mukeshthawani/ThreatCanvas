# utils.py
import streamlit as st
import pandas as pd
from threatcanvas.client import LLMClient
from threatcanvas.agent import get_response
from langchain.agents.agent_types import AgentType
import matplotlib.pyplot as plt
import io

def init_session_state():
    """Initialize session state variables"""
    if 'messages' not in st.session_state:
        st.session_state.messages = []
    if 'df' not in st.session_state:
        st.session_state.df = None
    if 'agent' not in st.session_state:
        st.session_state.agent = None

def create_chat_interface():
    """Create and manage the chat interface"""
    # Initialize session state
    init_session_state()
    
    if st.session_state.df is not None:
        # Dataset Preview
        with st.expander("Dataset Preview", expanded=False):
            st.dataframe(st.session_state.df.head())
        
        # Clear chat button
        if st.button("🗑️ Clear Chat", type="secondary"):
            st.session_state.messages = []
            st.rerun()
            
        # Chat container
        chat_container = st.container()
        
        with chat_container:
            # Display chat messages
            for message in st.session_state.messages:
                with st.chat_message(message["role"]):
                    st.markdown(message["content"])
                    
                    # If there's a plot in the message, display it
                    if 'plot' in message:
                        st.image(message['plot'])

        # Chat input - Always at the bottom
        if prompt := st.chat_input("Ask a question about the log data"):
            if st.session_state.agent is not None:
                # Add user message
                st.session_state.messages.append({"role": "user", "content": prompt})
                
                # Display user message
                with chat_container:
                    with st.chat_message("user"):
                        st.markdown(prompt)
                    
                    # Display assistant response
                    with st.chat_message("assistant"):
                        message_placeholder = st.empty()
                        
                        with st.spinner("Analyzing..."):
                            try:
                                response = st.session_state.agent.run(prompt)
                                
                                # Handle matplotlib plots if generated
                                plot_data = None
                                if 'plt' in locals() or 'plt' in globals():
                                    # Check if the plot actually contains data
                                    if len(plt.get_fignums()) > 0 and len(plt.gca().collections + plt.gca().patches + plt.gca().lines) > 0:
                                        buf = io.BytesIO()
                                        plt.savefig(buf, format='png')
                                        buf.seek(0)
                                        plot_data = buf.getvalue()
                                    plt.clf()
                                
                                message_placeholder.markdown(response)
                                if plot_data:
                                    st.image(plot_data)
                                
                                # Save message with plot if exists
                                message = {
                                    "role": "assistant",
                                    "content": response
                                }
                                if plot_data:
                                    message["plot"] = plot_data
                                st.session_state.messages.append(message)
                                
                            except Exception as e:
                                error_message = f"Error analyzing query: {str(e)}"
                                message_placeholder.error(error_message)
                                st.session_state.messages.append({
                                    "role": "assistant",
                                    "content": error_message
                                })
    else:
        st.info("Please upload a log file to start the analysis.")

def initialize_chat_agent(file_path):
    """Initialize the chat agent with the uploaded file"""
    try:
        # Load the dataframe
        df = pd.read_csv(file_path)
        st.session_state.df = df
        
        # Create the agent using the custom get_response function
        st.session_state.agent = get_response(
            df=df,
            verbose=True,
            agent_type=AgentType.OPENAI_FUNCTIONS,
            allow_dangerous_code=True,
            handle_parsing_errors=True
        )
        
        return True
        
    except Exception as e:
        st.error(f"Error initializing chat agent: {str(e)}")
        return False