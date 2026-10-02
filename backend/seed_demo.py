"""Fill the history database with SYNTHETIC analyses so the dashboard has something to show.

Usage:  python -m backend.seed_demo --n 150
Rows come from data/phishing_email_dataset.csv (fictional emails), spread across the last 14 days.
"""
import argparse
import os
import random
from datetime import datetime, timedelta, timezone

import pandas as pd

from backend.config import ROOT, Settings
from backend.database import Database
from backend.services.analysis_service import assess_email
from backend.utils.preprocessing import extract_sender_domain


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=150)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    s = Settings()
    db = Database(s.db_path)
    df = pd.read_csv(os.path.join(ROOT, "data", "phishing_email_dataset.csv"), keep_default_na=False)
    rng = random.Random(a.seed)
    sample = df.sample(n=min(a.n, len(df)), random_state=a.seed)
    now = datetime.now(timezone.utc)
    for r in sample.itertuples():
        result = assess_email(r.sender, r.subject, r.body, r.attachment_name, None, True, s.model_path)
        when = now - timedelta(days=rng.randint(0, 13), hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
        db.save_analysis(result, extract_sender_domain(r.sender), r.subject, when.isoformat(timespec="seconds"))
    print(f"Seeded {len(sample)} synthetic analyses into {s.db_path}")


if __name__ == "__main__":
    main()
