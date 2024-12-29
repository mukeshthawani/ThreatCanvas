from threatcanvas.client import LLMClient
from threatcanvas.prompts.pattern import ANALYSE_PROMPT
from threatcanvas.memory import retrieve_context, save_interaction

from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import PromptTemplate
from pydantic import BaseModel, Field

import pandas as pd
from typing import Dict, List, Tuple
import json
import streamlit as st


class Reasoning(BaseModel):
    pattern_type: str = Field(description="Name of the detected threat pattern")
    description: str = Field(description="Detailed explanation of the threat")
    confidence: float = Field(
        description="Confidence score for the prediction",
        ge=0,
        le=100
    )
    indicators: List[str] = Field(
        description="List of specific indicators that led to this conclusion"
    )
class Metrics(BaseModel):
    requests_per_second: float = Field(description="Calculated rate of requests")
    time_window_seconds: int = Field(description="Time window in seconds")

class ThreatPrediction(BaseModel):
    prediction: str = Field(
        description="Prediction result",
        pattern="^(normal|abnormal)$"
    )
    reasoning: Reasoning = Field(description="Detailed reasoning for the prediction")
    metrics: Metrics = Field(description="Performance metrics")

class LogProcessor:
    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        self.current_index = 0
        self.batch_size = 10
        self.current_batch_id = 0
        self.user_id = "hackathon"
        
    def get_next_batch(self) -> pd.DataFrame:
        """Read next batch of logs from CSV"""
        df = pd.read_csv(self.csv_path)
        batch = df.iloc[self.current_index:self.current_index + self.batch_size]
        self.current_index += self.batch_size
        if self.current_index >= len(df):
            self.current_index = 0
        self.current_batch_id += 1
        return batch
    
    def calculate_metrics(self, df: pd.DataFrame) -> Dict:
        """Calculate key metrics from log data"""
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        time_diff = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
        requests_per_second = len(df) / time_diff if time_diff > 0 else 1
        
        success_count = df[df['status'].between(200, 299)].shape[0]
        error_rate = ((len(df) - success_count) / len(df)) * 100 if len(df) > 0 else 0
        unique_ips = df['ip'].nunique()
        #st.dataframe(df)

        return {
            'requests_per_second': int(requests_per_second),
            'error_rate': round(error_rate, 1),
            'unique_ips': unique_ips
        }
    
    def analyze_patterns(self, df: pd.DataFrame) -> List[Dict]:
        """Analyze log patterns using LLM and calculate request rates"""
        patterns = []
        client = LLMClient.create()
        llm = client.get_llm()

        parser = JsonOutputParser(pydantic_object=ThreatPrediction)
        prompt = PromptTemplate(
            template=ANALYSE_PROMPT,
            input_variables=["log_summary", "context"],
            partial_variables={"format_instructions": parser.get_format_instructions()},
        )

        def create_log_summary(group_df):
            summary = {
                'ip': group_df['ip'].iloc[0],
                'method': group_df['method'].value_counts().to_dict(),
                'paths': group_df['path'].unique().tolist(),
                'status_codes': group_df['status'].value_counts().to_dict(),
                'user_agent': group_df['user_agent'].iloc[0],
                'request_count': len(group_df),
                'time_window': {
                    'start': group_df['timestamp'].min().strftime('%Y-%m-%d %H:%M:%S'),
                    'end': group_df['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
                }
            }
            return json.dumps(summary)
        
        for _, group in df.groupby('ip'):
            try:
                log_summary = create_log_summary(group)
                
                context = retrieve_context(
                    f"Previous log summary, IP: {group['ip'].iloc[0]}, User Agent: {group['user_agent'].iloc[0]}, Method: {group['method'].iloc[0]}",
                    self.user_id
                )
                
                chain = prompt | llm | parser

                response = chain.invoke({"log_summary": log_summary, "context":json.dumps(context)})   
                response['timestamp'] = group['timestamp'].iloc[0]  
                
                patterns.append(response)
                save_interaction(
                    self.user_id,
                    f"Log Summary- IP: {group['ip'].iloc[0]}, User Agent: {group['user_agent'].iloc[0]}, Method: {group['method'].iloc[0]}, Status: {group['status'].iloc[0]}",
                    f"Prediction: {response['prediction']}, Reasoning: {response['reasoning']['description']}"
                )

            except Exception as e:
                print(f"Error analyzing pattern: {e}")
        
        return patterns

    def process_logs(self) -> Tuple[Dict, List[Dict]]:
        """Process next batch of logs and return metrics and patterns"""
        df = self.get_next_batch()
        metrics = self.calculate_metrics(df)
        patterns = self.analyze_patterns(df)
        return metrics,patterns
  
"""
if __name__ == "__main__":
    processor = LogProcessor("data/access_logs.csv")
    metrics, patterns = processor.process_logs()
    print(metrics)
    print(patterns)
"""