from threatcanvas.client import LLMClient
import pandas as pd
import os
import re
from typing import List, Tuple
from tqdm import tqdm
import time

INPUT_FILE = "../data/Linux.csv"
PROMPT_STRATEGY = "CoT"  # Options: 'Self', 'CoT'
OUTPUT_FILE = "log_predictions.csv"
PROMPT_CANDIDATES_FILE = "prompts/prompt_candidates.txt" 
NUM_LOG_ENTRIES = 30
llm = LLMClient()

def filter_special_chars(s: str) -> str:
    """
    Remove special characters from a string except for wildcards (*) and spaces.
    """
    return re.sub(r'[^\w\s*]', '', s)

def generate_prompts(
    strategy: str,
    logs: List[str],
    prompt_candidates: List[str] = None,
) -> List[str]:
    """
    Generate prompts based on the selected strategy.

    :param strategy: 'Self', 'CoT', or 'InContext'
    :param logs: List of log strings
    :param examples: DataFrame with 'log' and 'label' columns for 'InContext'
    :param prompt_candidates: List of prompt templates for 'Self'
    :return: List of generated prompts
    """
    prompts = []
    if strategy == "CoT":
        prompt_header = (
            "Classify the following log entries as 'normal' or 'abnormal'. "
            "Provide a concise explanation for each classification.\n\n"
        )
        for log in logs:
            prompt = f"{prompt_header}Log: {log}\nClassification:"
            prompts.append(prompt)
    elif strategy == "Self":
        if prompt_candidates is None:
            raise ValueError("Prompt candidates are required for Self strategy.")
        for log in logs:
            prompt_candidate = prompt_candidates.pop(0) if prompt_candidates else ""
            prompt = f"{prompt_candidate}\nLog: {log}\nCategory:"
            prompts.append(prompt)
    else:
        raise ValueError("Invalid prompt strategy selected. Choose from 'Self', 'CoT', 'InContext'.")
    return prompts

def classify_logs_with_openai(
    prompts: List[str],
) -> List[str]:
    """
    Classify logs by sending prompts to OpenAI's API.

    :param prompts: List of prompts
    :param api_key: OpenAI API key
    :param model: OpenAI model to use
    :param max_retries: Maximum number of retries for API calls
    :param sleep_time: Seconds to wait before retrying after a failure
    :return: List of classifications ('normal', 'abnormal', 'unknown', 'error')
    """
    classifications = []

    for prompt in tqdm(prompts, desc="Classifying Logs"):
        try:
            classification = llm.get_response(
                system_prompt="Classify the following log entries as 'normal' or 'abnormal'.",
                prompt=prompt,
                conversation_history=[]
            )
            if 'normal' in classification:
                classifications.append('normal')
            elif 'abnormal' in classification:
                classifications.append('abnormal')
            else:
                classifications.append('abnormal')
        except Exception as e:
            print(e)
            classifications.append('error')
            break

    return classifications

def load_prompt_candidates(file_path: str) -> List[str]:
    """
    Load prompt candidates from a text file.

    :param file_path: Path to the prompt candidates text file
    :return: List of prompt candidates
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Prompt candidates file not found: {file_path}")
    with open(file_path, 'r', encoding='utf-8') as f:
        prompts = [line.strip() for line in f if line.strip()]
    if not prompts:
        raise ValueError("Prompt candidates file is empty.")
    return prompts

def load_examples(file_path: str) -> pd.DataFrame:
    """
    Load examples from an Excel or CSV file.

    :param file_path: Path to the example Excel or CSV file
    :return: DataFrame with 'log' and 'label' columns
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Example file not found: {file_path}")
    if file_path.endswith(".csv"):
        df = pd.read_csv(file_path)
    elif file_path.endswith((".xlsx", ".xls")):
        df = pd.read_excel(file_path)
    else:
        raise ValueError("Example file must be a CSV or Excel file.")
    if 'log' not in df.columns or 'label' not in df.columns:
        raise ValueError("Example file must contain 'log' and 'label' columns.")
    return df

def main():
    """
    Main function to perform anomaly detection on logs using OpenAI's LLM.
    """
    if not os.path.exists(INPUT_FILE):
        print(f"Input file not found: {INPUT_FILE}")
        return

    # Read the input CSV file
    try:
        if INPUT_FILE.endswith(".csv"):
            df_logs = pd.read_csv(INPUT_FILE)
        elif INPUT_FILE.endswith((".xlsx", ".xls")):
            df_logs = pd.read_excel(INPUT_FILE)
        else:
            print("Input file must be a CSV or Excel file.")
            return
    except Exception as e:
        print(f"Error reading the input file: {e}")
        return

    # Validate 'log' column
    if 'log' not in df_logs.columns:
        print("The input file must contain a 'log' column.")
        return

    # Select only the first NUM_LOG_ENTRIES logs
    df_logs = df_logs.head(NUM_LOG_ENTRIES).reset_index(drop=True)
    logs = df_logs['log'].astype(str).tolist()

    # Generate prompts based on the selected strategy
    try:
        if PROMPT_STRATEGY == "Self":
            if not PROMPT_CANDIDATES_FILE:
                raise ValueError("Prompt candidates file path must be provided for Self strategy.")
            prompt_candidates = load_prompt_candidates(PROMPT_CANDIDATES_FILE)
            # Ensure there are enough prompt candidates
            if len(prompt_candidates) < len(logs):
                # Repeat prompts if not enough
                multiplier = (len(logs) // len(prompt_candidates)) + 1
                prompt_candidates *= multiplier
            prompts = generate_prompts(
                strategy=PROMPT_STRATEGY,
                logs=logs,
                prompt_candidates=prompt_candidates
            )
        elif PROMPT_STRATEGY == "CoT":
            prompts = generate_prompts(
                strategy=PROMPT_STRATEGY,
                logs=logs
            )
        else:
            raise ValueError("Invalid prompt strategy selected. Choose from 'Self', 'CoT', 'InContext'.")
    except Exception as e:
        print(f"Error generating prompts: {e}")
        return

    try:
        predictions = classify_logs_with_openai(
            prompts=prompts,
        )
        print(predictions)
    except Exception as e:
        print(f"Error during classification: {e}")
        return

"""
if __name__ == "__main__":
    main()
"""