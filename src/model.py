from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

from src.feature_engineering import FEATURE_COLUMNS, get_feature_frame

ModelAlgorithm = Literal["isolation_forest", "one_class_svm"]


@dataclass
class ModelResult:
    predictions: pd.Series
    anomaly_score: pd.Series
    raw_anomaly_score: pd.Series


def _normalize_scores(scores: pd.Series) -> pd.Series:
    if scores.empty:
        return scores.copy()
    min_value = float(scores.min())
    max_value = float(scores.max())
    if max_value <= min_value:
        return pd.Series([0.0] * len(scores), index=scores.index, name="anomaly_score")
    return ((scores - min_value) / (max_value - min_value)).clip(0.0, 1.0).rename("anomaly_score")


class LogAnomalyModel:
    """Shared anomaly model wrapper for offline log monitoring."""

    # One-Class SVM (RBF) training is O(n^2). Above this many rows it is fitted
    # on a fixed-seed random sample and then scores every row. Isolation Forest
    # is unaffected. Datasets at or below the cap behave exactly as before.
    OCSVM_MAX_FIT_ROWS = 20_000

    def __init__(self, contamination: float = 0.12, random_state: int = 42, algorithm: ModelAlgorithm = "isolation_forest") -> None:
        self.contamination = contamination
        self.random_state = random_state
        self.algorithm = algorithm
        self.fit_rows = 0
        if algorithm == "one_class_svm":
            estimator = OneClassSVM(kernel="rbf", gamma="scale", nu=min(max(contamination, 0.01), 0.5))
        else:
            estimator = IsolationForest(
                # 100 trees keeps the detector stable while making large
                # offline batches practical; sklearn already subsamples each
                # tree, so more trees add cost without improving throughput.
                n_estimators=100,
                contamination=contamination,
                random_state=random_state,
                n_jobs=-1,
            )
        self.pipeline: Pipeline = Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                ("estimator", estimator),
            ]
        )
        self.is_fitted = False

    def fit(self, feature_frame: pd.DataFrame) -> "LogAnomalyModel":
        features = get_feature_frame(feature_frame).fillna(0)
        if features.empty:
            raise ValueError("Cannot fit the anomaly model on an empty dataset.")
        if self.algorithm == "one_class_svm" and len(features) > self.OCSVM_MAX_FIT_ROWS:
            features_for_fit = features.sample(n=self.OCSVM_MAX_FIT_ROWS, random_state=self.random_state)
        else:
            features_for_fit = features
        self.fit_rows = len(features_for_fit)
        self.pipeline.fit(features_for_fit)
        self.is_fitted = True
        return self

    def _raw_scores(self, features: pd.DataFrame) -> pd.Series:
        estimator = self.pipeline.named_steps["estimator"]
        if hasattr(estimator, "decision_function"):
            scores = -self.pipeline.decision_function(features)
        else:
            scores = -self.pipeline.score_samples(features)
        return pd.Series(scores, index=features.index, name="raw_anomaly_score")

    def predict(self, feature_frame: pd.DataFrame) -> ModelResult:
        if not self.is_fitted:
            raise RuntimeError("The model must be fitted before predictions are generated.")
        features = get_feature_frame(feature_frame).fillna(0)
        predictions = self.pipeline.predict(features)
        raw_scores = self._raw_scores(features)
        normalized_scores = _normalize_scores(raw_scores)
        return ModelResult(
            predictions=pd.Series(predictions, index=feature_frame.index, name="prediction"),
            anomaly_score=normalized_scores.rename("anomaly_score"),
            raw_anomaly_score=raw_scores,
        )

    def fit_predict(self, feature_frame: pd.DataFrame) -> pd.DataFrame:
        self.fit(feature_frame)
        result = self.predict(feature_frame)
        output = feature_frame.copy()
        output["prediction"] = result.predictions
        output["anomaly_score"] = result.anomaly_score
        output["raw_anomaly_score"] = result.raw_anomaly_score
        output["model_algorithm"] = self.algorithm
        return output

    @property
    def required_features(self) -> list[str]:
        return FEATURE_COLUMNS


class IsolationForestLogModel(LogAnomalyModel):
    """Backward-compatible Isolation Forest model wrapper."""

    def __init__(self, contamination: float = 0.12, random_state: int = 42, algorithm: ModelAlgorithm = "isolation_forest") -> None:
        super().__init__(contamination=contamination, random_state=random_state, algorithm=algorithm)
