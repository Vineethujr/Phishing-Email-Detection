"""Print dataset statistics (for docs and your 'dataset statistics' screenshot).  python data/dataset_stats.py"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pandas as pd
from backend.utils.preprocessing import preprocess_dataframe

path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phishing_email_dataset.csv")
raw = pd.read_csv(path, keep_default_na=False)
df = preprocess_dataframe(raw)
print("SYNTHETIC DATASET STATISTICS")
print(f"Generated rows        : {len(raw)}  {raw.label.value_counts().to_dict()}")
print(f"After de-duplication  : {len(df)}  {df.label.value_counts().to_dict()}  (removed {len(raw) - len(df)} duplicate rows)")
print(f"Rows with URLs        : {int((df.url_list.map(len) > 0).sum())}")
print(f"Rows with attachments : {int((df.attachment_name != '').sum())}")
print(f"Distinct sender domains: {df.sender_domain.nunique()}")
print("\nRows per category (after de-duplication):")
print(df.groupby(["label", "category"]).size().to_string())
print("\nAll domains are reserved/fictional: example.com/.org/.net, *.invalid.test, *.example; IPs from documentation ranges.")
