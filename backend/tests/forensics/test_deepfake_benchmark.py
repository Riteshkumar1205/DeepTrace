from __future__ import annotations

import math
import pytest
from typing import Dict, List, Any

# ---------------------------------------------------------
# Deepfake Benchmarking Metric Calculator
# ---------------------------------------------------------

class DeepfakeBenchmarkPipeline:
    @staticmethod
    def calculate_metrics(y_true: List[int], y_pred: List[int], y_scores: List[float]) -> Dict[str, float]:
        """
        Calculates Accuracy, Precision, Recall, F1 Score, and ROC-AUC.
        Handles zero-division edge cases gracefully.
        """
        tp = sum(1 for gt, pd in zip(y_true, y_pred) if gt == 1 and pd == 1)
        fp = sum(1 for gt, pd in zip(y_true, y_pred) if gt == 0 and pd == 1)
        fn = sum(1 for gt, pd in zip(y_true, y_pred) if gt == 1 and pd == 0)
        tn = sum(1 for gt, pd in zip(y_true, y_pred) if gt == 0 and pd == 0)

        total = len(y_true)
        accuracy = (tp + tn) / total if total > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        # Calculate ROC-AUC using trapezoidal approximation of sorted scores
        roc_auc = DeepfakeBenchmarkPipeline._calculate_roc_auc(y_true, y_scores)

        return {
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1_score, 4),
            "roc_auc": round(roc_auc, 4),
            "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}
        }

    @staticmethod
    def _calculate_roc_auc(y_true: List[int], y_scores: List[float]) -> float:
        """Helper to calculate Area Under the ROC Curve."""
        if not y_true or len(y_true) != len(y_scores):
            return 0.5
        
        # Check if only one class exists
        if len(set(y_true)) < 2:
            return 0.5

        # Pair scores with true outcomes and sort descending by score
        paired = sorted(zip(y_scores, y_true), key=lambda x: x[0], reverse=True)
        
        pos_count = sum(y_true)
        neg_count = len(y_true) - pos_count

        auc = 0.0
        fp_curr = 0
        tp_curr = 0
        fp_prev = 0
        tp_prev = 0
        last_score = float('inf')

        for score, label in paired:
            if score != last_score:
                auc += DeepfakeBenchmarkPipeline._trapezoid_area(fp_curr, fp_prev, tp_curr, tp_prev)
                last_score = score
                fp_prev = fp_curr
                tp_prev = tp_curr
            
            if label == 1:
                tp_curr += 1
            else:
                fp_curr += 1

        auc += DeepfakeBenchmarkPipeline._trapezoid_area(neg_count, fp_prev, pos_count, tp_prev)
        
        if pos_count * neg_count > 0:
            return auc / (pos_count * neg_count)
        return 0.5

    @staticmethod
    def _trapezoid_area(x1: float, x2: float, y1: float, y2: float) -> float:
        base = abs(x1 - x2)
        height_avg = (y1 + y2) / 2.0
        return base * height_avg


# ---------------------------------------------------------
# Test Cases
# ---------------------------------------------------------

@pytest.mark.forensics
def test_metrics_calculation_standard_case() -> None:
    y_true = [1, 1, 0, 0, 1, 0, 1, 0]
    y_pred = [1, 0, 0, 0, 1, 1, 1, 0]
    # Positives are indexes: 0, 1, 4, 6
    # Negatives are indexes: 2, 3, 5, 7
    # TP: 0, 4, 6 -> 3
    # FP: 5 -> 1
    # FN: 1 -> 1
    # TN: 2, 3, 7 -> 3

    y_scores = [0.9, 0.4, 0.1, 0.2, 0.8, 0.7, 0.95, 0.3]

    metrics = DeepfakeBenchmarkPipeline.calculate_metrics(y_true, y_pred, y_scores)

    assert metrics["accuracy"] == 0.75
    assert metrics["precision"] == 0.75  # 3 / (3 + 1)
    assert metrics["recall"] == 0.75  # 3 / (3 + 1)
    assert metrics["f1_score"] == 0.75
    assert metrics["roc_auc"] > 0.5


@pytest.mark.forensics
def test_metrics_zero_division_safety() -> None:
    # Test case where model predicts everything as negative (no positives predicted)
    y_true = [1, 0, 1]
    y_pred = [0, 0, 0]
    y_scores = [0.1, 0.2, 0.05]

    metrics = DeepfakeBenchmarkPipeline.calculate_metrics(y_true, y_pred, y_scores)

    assert metrics["precision"] == 0.0
    assert metrics["recall"] == 0.0
    assert metrics["f1_score"] == 0.0
    assert metrics["accuracy"] == 0.3333


@pytest.mark.forensics
def test_benchmark_variations() -> None:
    # Simulated datasets representing target configurations
    datasets = {
        "FaceForensics++": {
            "low_resolution": {"true": [1, 0, 1], "pred": [1, 0, 0], "scores": [0.9, 0.1, 0.45]},
            "high_compression": {"true": [1, 0, 1], "pred": [1, 0, 0], "scores": [0.85, 0.15, 0.4]},
        },
        "CelebDF": {
            "partial_faces": {"true": [1, 1, 0], "pred": [1, 1, 0], "scores": [0.92, 0.95, 0.2]},
            "multiple_faces": {"true": [1, 0, 1], "pred": [0, 0, 1], "scores": [0.3, 0.25, 0.88]},
        },
        "DFDC": {
            "occluded_faces": {"true": [1, 0], "pred": [1, 0], "scores": [0.75, 0.1]},
            "voice_cloned": {"true": [1, 1], "pred": [1, 1], "scores": [0.99, 0.98]},
        }
    }

    # Verify that all combinations calculate successfully without crashing
    for db_name, conditions in datasets.items():
        for condition, data in conditions.items():
            metrics = DeepfakeBenchmarkPipeline.calculate_metrics(
                data["true"], data["pred"], data["scores"]
            )
            assert "accuracy" in metrics
            assert "roc_auc" in metrics
            assert metrics["accuracy"] >= 0.0
            assert metrics["roc_auc"] >= 0.0
