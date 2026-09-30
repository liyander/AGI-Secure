"""Reproducible synthetic cohort for showing Fairlearn measurement and mitigation."""

from functools import lru_cache

import numpy as np
from fairlearn.metrics import MetricFrame, selection_rate
from fairlearn.postprocessing import ThresholdOptimizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score


def _summary(y_true, y_pred, group):
    frame = MetricFrame(metrics={"selection_rate": selection_rate, "accuracy": accuracy_score}, y_true=y_true, y_pred=y_pred, sensitive_features=group)
    rates = {str(key): round(float(value), 3) for key, value in frame.by_group["selection_rate"].items()}
    return {"selection_rate_by_group": rates, "selection_rate_gap": round(max(rates.values()) - min(rates.values()), 3), "accuracy": round(float(frame.overall["accuracy"]), 3)}


@lru_cache(maxsize=1)
def synthetic_fairness_demo() -> dict:
    rng = np.random.default_rng(21)
    n = 600
    group = np.array(["A", "B"] * (n // 2))
    skill = rng.normal(loc=np.where(group == "A", 0.35, -0.15), scale=1.0)
    experience = rng.normal(size=n)
    labels = (skill + 0.4 * experience + rng.normal(scale=0.55, size=n) > 0.1).astype(int)
    features = np.column_stack([skill, experience])
    order = rng.permutation(n)
    train, test = order[:400], order[400:]
    estimator = LogisticRegression(max_iter=500).fit(features[train], labels[train])
    baseline = estimator.predict(features[test])
    optimizer = ThresholdOptimizer(estimator=estimator, constraints="demographic_parity", objective="accuracy_score", prefit=True, predict_method="predict_proba")
    optimizer.fit(features[train], labels[train], sensitive_features=group[train])
    mitigated = optimizer.predict(features[test], sensitive_features=group[test], random_state=42)
    return {
        "sample": {"training": len(train), "evaluation": len(test), "features": ["synthetic skill", "synthetic experience"], "groups": ["A", "B"]},
        "baseline": _summary(labels[test], baseline, group[test]),
        "mitigated": _summary(labels[test], mitigated, group[test]),
        "method": "Fairlearn MetricFrame measures group selection rates. Fairlearn ThresholdOptimizer learns group-aware decision thresholds under a demographic-parity constraint on synthetic training data.",
        "limits": "This is a seeded toy cohort, not a hiring system. A fairness constraint can change accuracy, and parity on training data is not guaranteed on held-out data.",
    }
