import streamlit as st
import pandas as pd
from threatcanvas.processor import LogProcessor
from threatcanvas.agent import get_response
from threatcanvas.utils import chat_interface
import time
import os

st.set_page_config(page_title="🕵️‍♂️Threat Canvas", layout="wide")

# Initialize session state
if 'log_processor' not in st.session_state:
    st.session_state.log_processor = None
if 'file_uploaded' not in st.session_state:
    st.session_state.file_uploaded = False
if 'patterns' not in st.session_state:
    st.session_state.patterns = []
if 'df_agent' not in st.session_state:
    st.session_state.df_agent = None
if 'messages' not in st.session_state:
    st.session_state.messages = []
if 'file_path' not in st.session_state:
    st.session_state.file_path = None

def create_tabs():
    return st.tabs([
        "🕒 Real-time Monitoring",
        "📊 Periodic Summary",
        "🔍 Log Query",
        "📦 Data Center"
    ])

def display_metrics(metrics):
    cols = st.columns(5)
    with cols[0]:
        st.metric("Requests Per Second", metrics['requests_per_second'])
    with cols[1]:
        st.metric("Error Rate", f"{metrics['error_rate']}%")
    with cols[2]:
        st.metric("Unique IPs", metrics['unique_ips'])
    with cols[3]:
        st.metric("Active Threats", len(st.session_state.patterns))

def display_patterns(patterns):
    st.subheader("Detected Patterns")
    for pattern in patterns:
        # Determine the color based on prediction
        color = "🔴" if pattern['prediction'] == "abnormal" else "🟢"
        
        # Create expander title with prediction and confidence
        title = f"{color} {pattern['reasoning']['pattern_type']} - Confidence: {pattern['reasoning']['confidence']}%"
        
        with st.expander(title, expanded=True):
            st.markdown(f"**Status:** {pattern['prediction'].upper()}")
            st.markdown(f"**Description:** {pattern['reasoning']['description']}")
            
            st.markdown("**Indicators:**")
            for indicator in pattern['reasoning']['indicators']:
                st.markdown(f"- {indicator}")
                
            st.markdown("**Metrics:**")
            st.markdown(f"- Requests/sec: {pattern['metrics']['requests_per_second']:.2f}")
            st.markdown(f"- Time Window: {pattern['metrics']['time_window_seconds']:.1f} seconds")
            
            st.text(f"Detected at: {pattern['timestamp']}")

def save_uploaded_file(uploaded_file):
    """Save uploaded file to a temporary location and return the path"""
    try:
        temp_dir = "temp"
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir)
            
        file_path = os.path.join(temp_dir, uploaded_file.name)
        with open(file_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        return file_path
    except Exception as e:
        st.error(f"Error saving file: {e}")
        return None

def initialize_agent(file_path):
    """Initialize the DataFrame agent with the uploaded log file"""
    try:
        df = pd.read_csv(file_path)
        agent = get_response(df, verbose=True)
        return agent, df
    except Exception as e:
        st.error(f"Error initializing agent: {e}")
        return None, None


def display_periodic_summary(df):
    """Display periodic summary analysis of log data."""
    analyzer = LogAnalyzer(df)
    
    # Display metrics
    metrics = analyzer.analyze_traffic_patterns()
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Requests", metrics['total_requests'])
    with col2:
        st.metric("Requests/Minute", metrics['requests_per_minute'])
    with col3:
        st.metric("Error Rate", f"{metrics['error_rate']:.1f}%")
    with col4:
        st.metric("Success Rate", f"{metrics['success_rate']:.1f}%")
        
    # Display status distribution chart
    st.plotly_chart(analyzer.create_status_distribution_chart(), use_container_width=True)
    
    # Add filters for data exploration
    st.subheader("Log Data Explorer")
    col1, col2, col3 = st.columns(3)
    with col1:
        status_filter = st.multiselect(
            "Filter by Status Code",
            options=sorted(df['status'].unique())
        )
    with col2:
        method_filter = st.multiselect(
            "Filter by HTTP Method",
            options=sorted(df['method'].unique())
        )
    with col3:
        path_search = st.text_input("Search in Path")
        
    # Display filtered data
    filtered_df = analyzer.get_filtered_data(status_filter, method_filter, path_search)
    st.dataframe(filtered_df, use_container_width=True)

def main():
    with st.sidebar:
        st.title("Configuration")
        uploaded_file = st.file_uploader("Upload Log File (CSV)", type=['csv'])
        
        if uploaded_file is not None and not st.session_state.file_uploaded:
            file_path = save_uploaded_file(uploaded_file)
            if file_path:
                st.session_state.log_processor = LogProcessor(file_path)
                st.session_state.df_agent, _ = initialize_agent(file_path)
                st.session_state.file_path = file_path  # Save the file path
                st.session_state.file_uploaded = True
                st.session_state.messages = []  # Reset chat messages
                st.success("File uploaded and agent initialized successfully!")
    
    # Main content
    st.title("Threat Canvas Dashboard 🌐")
    
    if not st.session_state.file_uploaded:
        st.warning("Please upload a CSV file to begin analysis.")
        return
    
    tabs = create_tabs()
    
    with tabs[0]:
        col1, col2 = st.columns([2, 2])
        with col1:
            interval = st.number_input("seconds", min_value=1, value=20)
        with col2:
            st.text("sample interval")
            
        if st.button("Start Monitoring"):
            while True:
                metrics, patterns = st.session_state.log_processor.process_logs()
                st.session_state.patterns = patterns
                
                display_metrics(metrics)
                display_patterns(patterns)

                time.sleep(interval)
                st.rerun()
    
    with tabs[1]:
        st.info("Periodic Summary - Coming Soon")

    with tabs[2]:
        st.header("Chat with Log Analysis Agent")
        chat_interface()
    
    with tabs[3]:
        st.info("Data Center - Coming Soon")

if __name__ == "__main__":
    main()