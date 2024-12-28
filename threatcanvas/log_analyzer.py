import pandas as pd
import plotly.graph_objects as go
from datetime import datetime
import urllib.parse
import re
import json
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import boto3
import requests
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threatcanvas.config import config
import streamlit as st

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Application constants
DEFAULT_ANALYSIS_LINES = 1000
MAX_ANALYSIS_LINES = 10000
BEDROCK_MODEL_ID = "anthropic.claude-3-5-sonnet-20240620-v1:0"
MAX_TOKENS = 4096
AWS_REGION = 'ap-northeast-1'

@dataclass
class LogEntry:
    """Data class for parsed log entries"""
    id: str
    ip: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status: int
    bytes_sent: int
    referer: str
    user_agent: str

class LogAnalyzer:
    """Main class for log analysis functionality with AI-powered insights"""
    
    SYSTEM_PROMPT = """You are an expert security analyst. Analyze the provided logs and generate a detailed security report.
    Focus on identifying patterns, anomalies, and potential security concerns.
    Provide specific recommendations based on the observed patterns.
    Your response must be a valid JSON object with the exact structure provided."""

    ANALYSIS_TEMPLATE = {
        "http_status_distribution": "Distribution analysis of HTTP status codes",
        "suspicious_ip_activity": [
            {
                "ip": "IP address",
                "requests": "Number of requests",
                "comment": "Analysis of the activity"
            }
        ],
        "large_response_anomalies": [
            {
                "size": "Response size in bytes",
                "path": "Request path",
                "comment": "Analysis of the anomaly"
            }
        ],
        "suspicious_path_analysis": [
            {
                "path": "Suspicious path",
                "occurrences": "Number of occurrences",
                "comment": "Analysis of the suspicious activity"
            }
        ],
        "user_agent_analysis": {
            "browser_distribution": {
                "browser_name": "percentage"
            },
            "suspicious_agents": [
                "List of suspicious user agents"
            ]
        },
        "recommendations": [
            "List of security recommendations"
        ]
    }
    
    def __init__(self):
        self.bedrock_client = None
        self._initialize_bedrock()
    
    def analyze_traffic_patterns(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze traffic patterns and generate metrics"""
        metrics = {
            'total_requests': len(df),
            'unique_ips': len(df['ip'].unique()),
            'error_rate': (df['status'] >= 400).mean() * 100,
            'success_rate': (df['status'] == 200).mean() * 100,
            'requests_per_minute': 0,
            'avg_response_size': '0B'
        }
        
        if len(df) > 0:
            time_diff = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
            metrics['requests_per_minute'] = round((metrics['total_requests'] / time_diff) * 60, 1) if time_diff > 0 else metrics['total_requests']
        
        avg_bytes = df['bytes_sent'].mean()
        metrics['avg_response_size'] = self._format_bytes(avg_bytes)
        
        return metrics

    @staticmethod
    def _format_bytes(bytes_value: float) -> str:
        """Format bytes into human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024:
                return f"{bytes_value:.1f}{unit}"
            bytes_value /= 1024
        return f"{bytes_value:.1f}TB"

    def create_status_distribution_chart(self, df: pd.DataFrame) -> go.Figure:
        """Create an enhanced status code distribution chart"""
        def get_status_group(status):
            return (status // 100) * 100

        df['status_group'] = df['status'].apply(get_status_group)
        status_counts = df['status_group'].value_counts().sort_index()
        
        status_colors = {
            200: '#00CC96',  # Success - Green
            300: '#AB63FA',  # Redirect - Purple
            400: '#FFA15A',  # Client Error - Orange
            500: '#EF553B'   # Server Error - Red
        }

        fig = go.Figure()
        
        for status in status_counts.index:
            fig.add_trace(go.Bar(
                x=[status],
                y=[status_counts[status]],
                name=f"{status}s",
                marker_color=status_colors.get(status, '#636EFA'),
                hovertemplate="Status: %{x}<br>Count: %{y}<extra></extra>"
            ))

        fig.update_layout(
            title="HTTP Status Code Distribution",
            showlegend=True,
            plot_bgcolor='white',
            bargap=0.3,
            height=400,
            margin=dict(l=40, r=40, t=60, b=40),
            xaxis=dict(
                title="Status Code",
                ticktext=['2xx Success', '3xx Redirect', '4xx Client Error', '5xx Server Error'],
                tickvals=[200, 300, 400, 500]
            ),
            yaxis=dict(
                title="Count",
                gridcolor='rgba(0,0,0,0.1)',
                griddash='dot'
            )
        )
        
        return fig

    def generate_ai_summary(self, logs: List[str]) -> Optional[Dict[str, Any]]:
        """Generate AI-powered analysis summary using AWS Bedrock"""
        if not self.bedrock_client:
            logger.error("Bedrock client not initialized")
            return None

        try:
            # Sample logs if there are too many entries
            MAX_LOGS = 500  # Limit to 500 entries for analysis
            sampled_logs = logs[:MAX_LOGS] if len(logs) > MAX_LOGS else logs
            
            # Create a summary string instead of full logs
            log_summary = f"Analyzing {len(logs)} log entries (showing sample of {len(sampled_logs)}):\n"
            log_summary += "\n".join(sampled_logs)

            messages = [{
                "role": "user",
                "content": f"""Analyze these access logs and provide a security analysis report.
This is a sample of {len(sampled_logs)} entries from a total of {len(logs)} log entries.

Sample logs:
{log_summary}

Provide your analysis as a JSON object with these exact keys:
{json.dumps(self.ANALYSIS_TEMPLATE, indent=2)}

Ensure your response is a properly formatted JSON object with all specified sections."""
            }]

            response = self._generate_bedrock_message(
                messages=messages,
                max_tokens=MAX_TOKENS
            )
            
            if not response:
                return None

            summary = self._extract_json_from_text(response)
            if not summary:
                logger.error("Failed to parse AI response as JSON")
                return None

            for key in self.ANALYSIS_TEMPLATE.keys():
                if key not in summary:
                    logger.warning(f"Missing section in AI response: {key}")
                    summary[key] = "No analysis available"

            return summary

        except Exception as e:
            logger.error(f"Error generating AI summary: {e}", exc_info=True)
            return None

    def _generate_bedrock_message(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = MAX_TOKENS
    ) -> Optional[str]:
        """Generate a message using AWS Bedrock"""
        try:
            body = json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "system": self.SYSTEM_PROMPT,
                "max_tokens": max_tokens,
                "messages": messages
            })
            
            response = self.bedrock_client.invoke_model(
                body=body,
                modelId=BEDROCK_MODEL_ID
            )
            
            response_body = json.loads(response.get('body').read())
            return response_body.get('content')[0].get('text', '')
            
        except Exception as e:
            logger.error(f"Error generating Bedrock message: {e}", exc_info=True)
            return None

    def _extract_json_from_text(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract and parse JSON from text response"""
        try:
            json_pattern = r'\{[\s\S]*\}'
            matches = re.findall(json_pattern, text)
            
            if not matches:
                logger.error("No JSON content found in text")
                return None
                
            for match in matches:
                try:
                    return json.loads(match.strip())
                except json.JSONDecodeError:
                    continue
                    
            logger.error("Could not parse any JSON content")
            return None
            
        except Exception as e:
            logger.error(f"Error extracting JSON: {e}", exc_info=True)
            return None
        
    def _initialize_bedrock(self) -> None:
        """Initialize AWS Bedrock client with error handling"""
        try:
            if not config.AWS_ACCESS_KEY_ID or not config.AWS_SECRET_ACCESS_KEY:
                logger.error("AWS credentials not configured")
                st.error("AWS credentials not configured. AI analysis features will be disabled.")
                self.bedrock_client = None
                return

            self.bedrock_client = boto3.client(
                service_name='bedrock-runtime',
                aws_access_key_id=config.AWS_ACCESS_KEY_ID,
                aws_secret_access_key=config.AWS_SECRET_ACCESS_KEY,
                region_name=AWS_REGION
            )
        except Exception as e:
            logger.error(f"Failed to initialize Bedrock client: {e}", exc_info=True)
            st.error("Failed to initialize AI analysis capabilities. Some features may be limited.")
            self.bedrock_client = None

    def parse_logs(self, log_file_path: str, max_lines: int = DEFAULT_ANALYSIS_LINES) -> List[LogEntry]:
        """Parse log entries from a CSV file"""
        try:
            df = pd.read_csv(
                log_file_path,
                nrows=max_lines,
                escapechar='\\',
                na_values=['-'],
                dtype={
                    'id': str,
                    'ip': str,
                    'timestamp': str,
                    'method': str,
                    'path': str,
                    'protocol': str,
                    'status': str,
                    'bytes_sent': str,
                    'referer': str,
                    'user_agent': str
                }
            )
            
            if df.empty:
                logger.error("No data found in the log file")
                return []

            log_entries = []
            for _, row in df.iterrows():
                try:
                    method = row['method'].strip('"')
                    timestamp = datetime.strptime(row['timestamp'], '%Y-%m-%d %H:%M:%S %z')
                    
                    try:
                        bytes_sent = int(row['bytes_sent'])
                    except (ValueError, TypeError):
                        bytes_sent = 0
                        
                    try:
                        status = int(row['status'])
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid status code for entry {row['id']}, skipping")
                        continue

                    log_entry = LogEntry(
                        id=str(row['id']),
                        ip=row['ip'],
                        timestamp=timestamp,
                        method=method,
                        path=row['path'],
                        protocol=row['protocol'].strip('"'),
                        status=status,
                        bytes_sent=bytes_sent,
                        referer=row['referer'].strip('"'),
                        user_agent=row['user_agent'].strip('"')
                    )
                    log_entries.append(log_entry)
                except Exception as e:
                    logger.warning(f"Error parsing log entry {row['id']}: {str(e)}")
                    continue

            if not log_entries:
                logger.error("No valid log entries found after parsing")
                return []

            logger.info(f"Successfully parsed {len(log_entries)} log entries")
            return log_entries

        except Exception as e:
            logger.error(f"Error reading log file: {str(e)}")
            return []