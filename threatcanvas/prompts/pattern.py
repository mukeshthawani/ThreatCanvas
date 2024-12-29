ANALYSE_PROMPT = """
Analyze the following web server log activity summary and determine if it represents normal or anomalous behavior. 
Leverage any stored memory CONTEXT of past log summaries to identify recurring patterns of fraudulent or abnormal activity. 
Use these past instances as a benchmark to enhance the detection of anomalies.

Consider the following factors comprehensively:

### Request Frequency and Patterns:
- Evaluate the number of requests per second and identify if there are spikes or deviations from normal traffic patterns.
- Compare against historical patterns to detect potential anomalies.

### Status Code Distribution:
- Analyze the proportion of HTTP status codes (e.g., 2xx, 3xx, 4xx, 5xx) and identify any abnormal ratios, especially if similar patterns were flagged as anomalous in the past.

### Path Access Patterns:
- Examine accessed paths for unusual repetition or targeting of specific resources.
- Cross-check against historically flagged malicious or abnormal paths.

### User Agent Legitimacy:

- Identify if user_agent values match legitimate browsers or known bots (e.g., Googlebot or Mozilla bot).
- If you encounter a user agent with bot, flag it as abnormal. 

### HTTP Method Usage:
- Assess the usage of HTTP methods (e.g., GET, POST, PUT, DELETE) for atypical distributions.
- Compare against historically abnormal method patterns, such as excessive POST requests.

Use the previous CONTEXT, and see if the IP is already mentioned in the past logs, its repetition, then mark it abnormal.

Provide your analysis in the specified JSON format, including prediction, detailed reasoning with confidence score, and metrics.

Make a deep breath and return results in JSON format only:
- Prediction: 'normal' or 'abnormal'
- Reasoning: Includes ``pattern type``, ``description``, ``confidence``, and ``indicators`` keys within the reasoning object.
- Metrics: Includes ``requests_per_second`` and ``time_window_seconds`` keys within the metrics object.

CONTEXT: {context}
Log activity summary: {log_summary} \n
{format_instructions}
"""