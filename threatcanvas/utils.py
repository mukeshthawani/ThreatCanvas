import streamlit as st
import matplotlib.pyplot as plt
import io

def chat_interface():
    """Display the chat interface with fixed viewport layout"""
    # Add custom CSS to control the chat container height and layout
    # Create main chat container
    main_container = st.container()
    
    # Add clear chat button
    _, right_col = st.columns([6, 1])
    with right_col:
        if st.button("Clear Chat"):
            st.session_state.messages = []
            st.rerun()
    
    # Initialize welcome message
    if not st.session_state.messages:
        st.session_state.messages.append({
            "role": "assistant",
            "content": "👋 Hello! I'm your log analysis assistant. I can help you analyze and visualize your log data"
        })
    
    # Create chat layout with fixed height
    with main_container:
        st.markdown('<div class="chat-container">', unsafe_allow_html=True)
        
        # Messages container
        with st.container():
            st.markdown('<div class="messages-container">', unsafe_allow_html=True)
            for message in st.session_state.messages:
                with st.chat_message(message["role"]):
                    st.markdown(message["content"])
            st.markdown('</div>', unsafe_allow_html=True)
        
        # Input container
        input_container = st.container()
        with input_container:
            if prompt := st.chat_input("Ask a question about your log data"):
                if st.session_state.df_agent is not None:
                    # Add user message
                    st.session_state.messages.append({"role": "user", "content": prompt})
                    
                    # Add user message to chat
                    with st.chat_message("user"):
                        st.markdown(prompt)
                    
                    # Process and display response
                    with st.chat_message("assistant"):
                        with st.spinner("Analyzing logs..."):
                            try:
                                response = st.session_state.df_agent.run(prompt)
                                
                                # Handle plots if generated
                                if 'plt' in locals() or 'plt' in globals():
                                    buf = io.BytesIO()
                                    plt.savefig(buf, format='png')
                                    buf.seek(0)
                                    st.image(buf)
                                    plt.clf()
                                
                                st.markdown(response)
                                st.session_state.messages.append({
                                    "role": "assistant",
                                    "content": response
                                })
                            except Exception as e:
                                error_message = f"I encountered an error while processing your request: {str(e)}"
                                st.error(error_message)
                                st.session_state.messages.append({
                                    "role": "assistant",
                                    "content": error_message
                                })
                    
                    st.rerun()
        
        st.markdown('</div>', unsafe_allow_html=True)