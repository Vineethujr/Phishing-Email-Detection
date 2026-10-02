"""Metrics and plots. Nothing here invents numbers: everything is computed from predictions."""
from typing import Dict, Sequence

import matplotlib
matplotlib.use("Agg")  # no display needed
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score


def compute_metrics(y_true: Sequence[int], y_pred: Sequence[int]) -> Dict:
    """Binary metrics with PHISHING = 1. tn/fp/fn/tp come from the confusion matrix."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp),
    }


def plot_confusion_matrix(metrics: Dict, title: str, path: str) -> None:
    cm = [[metrics["tn"], metrics["fp"]], [metrics["fn"], metrics["tp"]]]
    fig, ax = plt.subplots(figsize=(4.6, 4))
    ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1], ["Legitimate", "Phishing"])
    ax.set_yticks([0, 1], ["Legitimate", "Phishing"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(title, fontsize=10)
    labels = [["TN", "FP"], ["FN", "TP"]]
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{labels[i][j]}\n{cm[i][j]}", ha="center", va="center",
                    color="white" if cm[i][j] > max(map(max, cm)) / 2 else "black", fontsize=12)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)


def plot_model_comparison(results: Dict[str, Dict], path: str) -> None:
    names = list(results)
    fig, ax = plt.subplots(figsize=(7, 4))
    w = 0.2
    for k, key in enumerate(["accuracy", "precision", "recall", "f1"]):
        ax.bar([i + k * w for i in range(len(names))], [results[n][key] for n in names], w, label=key)
    ax.set_xticks([i + 1.5 * w for i in range(len(names))], names, fontsize=8)
    ax.set_ylim(0, 1.05)
    ax.set_title("Test-set metrics by detector")
    ax.legend(fontsize=8, loc="lower right")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
