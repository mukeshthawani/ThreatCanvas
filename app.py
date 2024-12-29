# Standard library imports
import os
import re
import json
import time
from datetime import datetime
#import logging
#import smtplib
#import urllib.parse
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
#from email.mime.text import MIMEText
#from email.mime.multipart import MIMEMultipart
# Third-party imports
import pandas as pd
import streamlit as st
import plotly.graph_objects as go
# Local imports
from threatcanvas.config import config  # Import the config instance
from threatcanvas.processor import LogProcessor
from threatcanvas.agent import get_response
from threatcanvas.log_analyzer import (
    LogAnalyzer,
    LogEntry,
    MAX_ANALYSIS_LINES,
    DEFAULT_ANALYSIS_LINES,
)
from threatcanvas.utils import (
    create_chat_interface, 
    initialize_chat_agent
)

st.set_page_config(page_title="🕵️‍♂️Threat Canvas", layout="wide")

if "log_processor" not in st.session_state:
    st.session_state.log_processor = None
if "file_uploaded" not in st.session_state:
    st.session_state.file_uploaded = False
if "patterns" not in st.session_state:
    st.session_state.patterns = []
if "df_agent" not in st.session_state:
    st.session_state.df_agent = None
if "messages" not in st.session_state:
    st.session_state.messages = []
if "file_path" not in st.session_state:
    st.session_state.file_path = None
if "log_analyzer" not in st.session_state:
    st.session_state.log_analyzer = LogAnalyzer()
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = None
if "metrics" not in st.session_state:
    st.session_state.metrics = None
if "filtered_df" not in st.session_state:
    st.session_state.filtered_df = None
if "ai_analysis_status" not in st.session_state:
    st.session_state.ai_analysis_status = "not_started"

def create_tabs():
    return st.tabs([
        "🕒 Real-time Monitoring","📊 Periodic Summary","🔍 Log Query","📦 Data Center"
    ])

def save_batch_data(patterns, batch_id, metrics):
    """Save batch data to data center folder"""
    data_center = "data_center"
    if not os.path.exists(data_center):
        os.makedirs(data_center)
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    batch_data = {
        "batch_id": batch_id,
        "timestamp": timestamp,
        "patterns": patterns,
        "metrics": metrics
    }
    
    file_path = os.path.join(data_center, f"batch_{batch_id}_{timestamp}.json")
    with open(file_path, "w") as f:
        json.dump(batch_data, f, indent=4, default=str)

def get_active_threats(patterns):
    """Count number of abnormal activities"""
    return sum(1 for pattern in patterns if pattern['prediction'] == 'abnormal')

def display_metrics(metrics, active_threats):
    cols = st.columns(4)
    with cols[0]:
        st.metric("Requests Per Second", metrics['requests_per_second'])
    with cols[1]:
        st.metric("Error Rate", f"{metrics['error_rate']}%")
    with cols[2]:
        st.metric("Unique IPs", metrics['unique_ips'])
    with cols[3]:
        st.metric("Active Threats", active_threats)

def display_abnormal_patterns(patterns):
    st.subheader("Detected Abnormal Activities")
    abnormal_patterns = [p for p in patterns if p['prediction'] == 'abnormal']
    
    if not abnormal_patterns:
        st.info("No abnormal activities detected in this batch.")
        return
        
    for pattern in abnormal_patterns:
        with st.expander(f"🔴 {pattern['reasoning']['pattern_type']} - Confidence: {pattern['reasoning']['confidence']}%", expanded=True):
            st.markdown(f"**Description:** {pattern['reasoning']['description']}")
            
            st.markdown("**Indicators:**")
            for indicator in pattern['reasoning']['indicators']:
                st.markdown(f"- {indicator}")
                
            st.markdown("**Metrics:**")
            st.markdown(f"- Requests/sec: {pattern['metrics']['requests_per_second']:.2f}")
            st.markdown(f"- Time Window: {pattern['metrics']['time_window_seconds']:.1f} seconds")
            
            st.text(f"Detected at: {pattern['timestamp']}")

def display_periodic_summary():
    """Display the periodic summary tab with log analyzer functionality"""
    st.header("📊 Periodic Analysis Summary")

    if not st.session_state.file_uploaded:
        st.warning("Please upload a log file to view analysis.")
        return

    try:
        # Display metrics in a clean grid
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric(
                "Requests/Minute", st.session_state.metrics["requests_per_minute"]
            )
        with col2:
            st.metric(
                "Avg Response Size", st.session_state.metrics["avg_response_size"]
            )
        with col3:
            st.metric("Error Rate", f"{st.session_state.metrics['error_rate']:.1f}%")
        with col4:
            st.metric("Unique IPs", st.session_state.metrics["unique_ips"])

        # Display status distribution chart
        st.plotly_chart(
            st.session_state.log_analyzer.create_status_distribution_chart(
                st.session_state.filtered_df
            ),
            use_container_width=True,
        )

        # Interactive data explorer
        st.subheader("Log Data Explorer")

        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            status_filter = st.multiselect(
                "Filter by Status Code",
                options=sorted(st.session_state.filtered_df["status"].unique()),
            )
        with col2:
            method_filter = st.multiselect(
                "Filter by HTTP Method",
                options=sorted(st.session_state.filtered_df["method"].unique()),
            )
        with col3:
            path_search = st.text_input("Search in Path")

        # Apply filters
        filtered_view = st.session_state.filtered_df.copy()
        if status_filter:
            filtered_view = filtered_view[filtered_view["status"].isin(status_filter)]
        if method_filter:
            filtered_view = filtered_view[filtered_view["method"].isin(method_filter)]
        if path_search:
            filtered_view = filtered_view[
                filtered_view["path"].str.contains(path_search, case=False)
            ]

        # Display filtered data
        st.dataframe(
            filtered_view.style.highlight_between(
                subset=["status"],
                left=400,
                right=600,
                props="background-color: rgba(255,0,0,0.2)",
            ),
            use_container_width=True,
        )

        # AI Analysis Section
        st.header("🔍 AI-Powered Security Analysis")
        
        # Check if we need to generate AI analysis
        if st.session_state.ai_analysis_status == "not_started":
            with st.spinner("Generating AI-powered security analysis..."):
                log_entries = [str(entry) for entry in st.session_state.filtered_df.itertuples()]
                st.session_state.analysis_results = st.session_state.log_analyzer.generate_ai_summary(log_entries)
                if st.session_state.analysis_results is not None:
                    st.session_state.ai_analysis_status = "completed"
                    st.rerun()  # Rerun to show the results immediately
                else:
                    st.error("Failed to generate AI analysis. Please try again.")
                    st.session_state.ai_analysis_status = "failed"
        
        # Display AI analysis results if available
        analysis_results = st.session_state.analysis_results
        if isinstance(analysis_results, dict):
            # HTTP Status Distribution
            if "http_status_distribution" in analysis_results:
                st.subheader("HTTP Status Distribution")
                st.write(analysis_results["http_status_distribution"])

            # Suspicious IP Activity
            if "suspicious_ip_activity" in analysis_results:
                st.subheader("⚠️ Suspicious IP Activity")
                for activity in analysis_results["suspicious_ip_activity"]:
                    with st.expander(f"IP: {activity['ip']} - {activity.get('requests', 'N/A')} requests", expanded=True):
                        cols = st.columns([2, 1])
                        with cols[0]:
                            if "comment" in activity:
                                st.markdown("**Analysis:**")
                                st.write(activity["comment"])
                            if "methods" in activity:
                                st.markdown("**HTTP Methods:**")
                                for method, count in activity["methods"].items():
                                    st.write(f"- {method}: {count} requests")
                        with cols[1]:
                            if "status_codes" in activity:
                                st.markdown("**Status Codes:**")
                                for status, count in activity["status_codes"].items():
                                    st.write(f"- {status}: {count} responses")
                            if "time_window" in activity:
                                st.markdown("**Time Window:**")
                                st.write(f"- Start: {activity['time_window'].get('start', 'N/A')}")
                                st.write(f"- End: {activity['time_window'].get('end', 'N/A')}")

            # Large Response Anomalies
            if "large_response_anomalies" in analysis_results:
                st.subheader("📊 Large Response Anomalies")
                for anomaly in analysis_results["large_response_anomalies"]:
                    with st.expander(f"Path: {anomaly['path']}", expanded=True):
                        cols = st.columns([2, 1])
                        with cols[0]:
                            st.markdown("**Details:**")
                            st.write(f"- Size: {st.session_state.log_analyzer._format_bytes(float(anomaly['size']))}")
                            if "comment" in anomaly:
                                st.markdown("**Analysis:**")
                                st.write(anomaly["comment"])
                            if "frequency" in anomaly:
                                st.write(f"- Frequency: {anomaly['frequency']} requests")
                        with cols[1]:
                            if "status_distribution" in anomaly:
                                st.markdown("**Status Distribution:**")
                                for status, count in anomaly["status_distribution"].items():
                                    st.write(f"- {status}: {count}")
                            if "time_detected" in anomaly:
                                st.markdown("**Detection Time:**")
                                st.write(anomaly["time_detected"])

            # Suspicious Path Analysis
            if "suspicious_path_analysis" in analysis_results:
                st.subheader("🔍 Suspicious Path Analysis")
                for path_info in analysis_results["suspicious_path_analysis"]:
                    with st.expander(f"Path: {path_info['path']}", expanded=True):
                        cols = st.columns([2, 1])
                        with cols[0]:
                            st.markdown("**Activity Details:**")
                            st.write(f"- Occurrences: {path_info['occurrences']}")
                            if "comment" in path_info:
                                st.markdown("**Analysis:**")
                                st.write(path_info["comment"])
                            if "risk_level" in path_info:
                                st.markdown("**Risk Level:**")
                                risk_color = {
                                    "high": "🔴",
                                    "medium": "🟡",
                                    "low": "🟢"
                                }.get(path_info["risk_level"].lower(), "⚪")
                                st.write(f"{risk_color} {path_info['risk_level']}")
                        with cols[1]:
                            if "method_distribution" in path_info:
                                st.markdown("**HTTP Methods:**")
                                for method, count in path_info["method_distribution"].items():
                                    st.write(f"- {method}: {count}")
                            if "status_codes" in path_info:
                                st.markdown("**Status Codes:**")
                                for status, count in path_info["status_codes"].items():
                                    st.write(f"- {status}: {count}")
                            if "first_seen" in path_info:
                                st.markdown("**First Seen:**")
                                st.write(path_info["first_seen"])

            # User Agent Analysis
            if "user_agent_analysis" in analysis_results:
                st.subheader("🌐 User Agent Analysis")
                col1, col2 = st.columns(2)

                with col1:
                    st.write("Browser Distribution:")
                    browser_dist = analysis_results["user_agent_analysis"]["browser_distribution"]
                    for browser, percentage in browser_dist.items():
                        st.write(f"- {browser}: {percentage}")

                with col2:
                    st.write("Suspicious User Agents:")
                    for agent in analysis_results["user_agent_analysis"]["suspicious_agents"]:
                        st.write(f"- {agent}")

            # Security Recommendations
            if "recommendations" in analysis_results:
                st.subheader("🛡️ Security Recommendations")
                for recommendation in analysis_results["recommendations"]:
                    st.write(f"• {recommendation}")

    except Exception as e:
        st.error(f"Error displaying periodic summary: {str(e)}")

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
    
def process_uploaded_file(file_path):
    """Process the uploaded file with both log processor and analyzer"""
    try:
        # Initialize log processor
        st.session_state.log_processor = LogProcessor(file_path)
        # Initialize log analyzer components
        log_entries = st.session_state.log_analyzer.parse_logs(file_path)
        if log_entries:
            st.session_state.filtered_df = pd.DataFrame(
                [vars(entry) for entry in log_entries]
            )
            st.session_state.metrics = (
                st.session_state.log_analyzer.analyze_traffic_patterns(
                    st.session_state.filtered_df
                )
            )
            st.session_state.ai_analysis_status = "not_started"

        # Initialize agent
        if initialize_chat_agent(file_path):
            st.success("File uploaded and analysis agents initialized successfully!")
        else:
            st.error("Error initializing chat agent")
        return True
    except Exception as e:
        st.error(f"Error processing file: {str(e)}")
        return False

def main():
    with st.sidebar:
        st.title("Configuration")
        uploaded_file = st.file_uploader("Upload Log File (CSV)", type=["csv"])
        if uploaded_file is not None and not st.session_state.file_uploaded:
            file_path = save_uploaded_file(uploaded_file)
            if file_path:
                if process_uploaded_file(file_path):
                    st.session_state.file_path = file_path
                    st.session_state.file_uploaded = True
                    st.session_state.messages = []
                    st.success("File uploaded and processed successfully!")
    
    # Main content
    st.title("Threat Canvas Dashboard 🌐")
    
    if not st.session_state.file_uploaded:
        st.warning("Please upload a CSV file to begin analysis.")
        return
    
    tabs = create_tabs()
    
    with tabs[0]:
        col1, col2 = st.columns([2, 2])
        with col1:
            interval = st.number_input("seconds-per interval", min_value=1, value=30)
            
        if st.button("Start Monitoring"):
            while True:
                metrics, patterns = st.session_state.log_processor.process_logs()
                active_threats = get_active_threats(patterns)
                
                save_batch_data(
                    patterns, 
                    st.session_state.log_processor.current_batch_id,
                    metrics
                )
                
                display_metrics(metrics, active_threats)
                display_abnormal_patterns(patterns)

                time.sleep(interval)
                st.rerun()
    
    with tabs[1]:
        st.header("Periodic Analysis Summary")
        if tabs[1].button("Analyze"):
            display_periodic_summary()

    with tabs[2]:
        st.header("Chat with Log Analysis Agent")
        create_chat_interface()
    
    with tabs[3]:
        st.header("Data Center")
        if os.path.exists("data_center"):
            files = os.listdir("data_center")
            if files:
                selected_file = st.selectbox("Select batch to view", files)
                if selected_file:
                    with open(os.path.join("data_center", selected_file)) as f:
                        batch_data = json.load(f)
                        st.json(batch_data)
            else:
                st.info("No batch data available yet.")
        else:
            st.info("Data center storage not initialized yet.")

if __name__ == "__main__":
    main()