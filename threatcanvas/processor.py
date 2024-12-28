from threatcanvas.client import LLMClient
from threatcanvas.prompts.pattern import ANALYSE_PROMPT

import pandas as pd
from typing import Dict, List, Tuple
import json
import re

class LogProcessor:
    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        self.current_index = 0
        self.batch_size = 30
        
    def get_next_batch(self) -> pd.DataFrame:
        """Read next batch of logs from CSV"""
        df = pd.read_csv(self.csv_path)
        batch = df.iloc[self.current_index:self.current_index + self.batch_size]
        self.current_index += self.batch_size
        if self.current_index >= len(df):
            self.current_index = 0
        return batch
    
    def calculate_metrics(self, df: pd.DataFrame) -> Dict:
        """Calculate key metrics from log data"""
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        time_diff = (df['timestamp'].max() - df['timestamp'].min()).total_seconds()
        requests_per_second = len(df) / time_diff if time_diff > 0 else 0
        
        success_count = df[df['status'].between(200, 299)].shape[0]
        error_rate = ((len(df) - success_count) / len(df)) * 100 if len(df) > 0 else 0
        unique_ips = df['ip'].nunique()
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
                # Calculate time window and request rate for this group
                time_diff = (group['timestamp'].max() - group['timestamp'].min()).total_seconds()
                requests_per_second = len(group) / time_diff if time_diff > 0 else len(group)

                log_summary = create_log_summary(group)
                response = llm.invoke(ANALYSE_PROMPT + log_summary + "FORCE OUTPUT JSON")
                pattern = r"```json(.*?)```"
                
                matches = re.findall(pattern, response.content, flags=re.DOTALL)
                
                if matches:
                    pattern = json.loads(matches[0].strip())
                
                pattern['timestamp'] = group['timestamp'].iloc[0]
                patterns.append(pattern)
            except Exception as e:
                print(f"Error analyzing pattern: {e}")
        print(patterns)
        return patterns

    def process_logs(self) -> Tuple[Dict, List[Dict]]:
        """Process next batch of logs and return metrics and patterns"""
        df = self.get_next_batch()
        metrics = self.calculate_metrics(df)
        patterns = self.analyze_patterns(df)
        return metrics,patterns