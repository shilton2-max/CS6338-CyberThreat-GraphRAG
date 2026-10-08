import csv
import tempfile
import unittest
from pathlib import Path
from ctirag.evaluate import summarize_human_scores

class TestHuman(unittest.TestCase):
    def test_human_summary(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / 'review.csv'
            rows = [
                {'question_id':'Q01','mode':'text','factuality_1_to_5':3,'completeness_1_to_5':4,'coherence_1_to_5':5},
                {'question_id':'Q01','mode':'hybrid','factuality_1_to_5':4,'completeness_1_to_5':5,'coherence_1_to_5':5},
            ]
            with p.open('w',newline='') as f:
                w=csv.DictWriter(f,fieldnames=list(rows[0]))
                w.writeheader()
                w.writerows(rows)
            result = summarize_human_scores(p)
            self.assertEqual(result['distinct_questions'],1)
            self.assertEqual(result['modes']['hybrid']['mean_factuality_1_to_5'],4)
