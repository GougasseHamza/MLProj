from pathlib import Path
import argparse
import hashlib
import json
import platform
import time
import warnings

import cloudpickle
import numpy as np
import pandas as pd
import scipy
from scipy import sparse
import sklearn
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.compose import ColumnTransformer
from sklearn.exceptions import ConvergenceWarning
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, classification_report, log_loss
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import StandardScaler, OneHotEncoder, FunctionTransformer
from sklearn.tree import DecisionTreeClassifier, export_text
from threadpoolctl import threadpool_limits


def finite(values):
    return values.replace([np.inf, -np.inf], np.nan)


def save_json(name, values):
    (out / name).write_text(json.dumps(values, indent=2))


class PortEncoder(TransformerMixin, BaseEstimator):
    def fit(self, values, y=None):
        values = np.asarray(values, dtype=float)
        self.ports_ = np.unique(values[np.isfinite(values)])
        assert (self.ports_ >= 0).all()
        self.encoder_ = OneHotEncoder(categories=[np.r_[-1, self.ports_]])
        self.encoder_.fit(self.ports_.reshape(-1, 1))
        return self

    def transform(self, values):
        values = np.asarray(values, dtype=float).copy()
        values[~np.isin(values, self.ports_)] = -1
        return self.encoder_.transform(values)

    def get_feature_names_out(self, input_features=None):
        return self.encoder_.get_feature_names_out(input_features)


root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument("--data-dir", type=Path, default=root / "MachineLearningCVE")
parser.add_argument("--output-dir", type=Path, default=root / "lab3_inputs")
args = parser.parse_args()
out = args.output_dir.resolve()
if out.exists() and any(out.iterdir()):
    raise SystemExit("Choose an empty output folder.")
out.mkdir(parents=True, exist_ok=True)
save_json("run_status.json", {"status": "running"})
started = time.perf_counter()
thread_limit = threadpool_limits(limits=6)

files = sorted(args.data_dir.glob("*.csv"))
assert len(files) == 8
df = pd.concat([pd.read_csv(f).rename(columns=str.strip).assign(source_file=f.name)
                for f in files], ignore_index=True)
df.index.name = "row_id"
features = [c for c in df if c not in ["Label", "source_file"]]
raw_rows = len(df)
duplicates = df.duplicated(features + ["Label"])
df = df.loc[~duplicates].copy()
conflicts = df.loc[df.duplicated(features, keep=False), features + ["Label"]]
conflicts.to_csv(out / "conflicting_labels.csv")
assert df["Label"].notna().all()

train, rest = train_test_split(df.index, test_size=0.30, stratify=df["Label"], random_state=42)
val, test = train_test_split(rest, test_size=0.50, stratify=df.loc[rest, "Label"], random_state=42)
parts = {"train": train, "validation": val, "test": test}
counts = pd.DataFrame({name: df.loc[rows, "Label"].value_counts()
                       for name, rows in parts.items()}).fillna(0).astype(int)
counts.to_csv(out / "class_counts.csv")
for name, rows in parts.items():
    pd.Series(rows, name="row_id").to_csv(out / f"{name}_ids.csv", index=False)
pd.Series({"seed": 42, "files": len(files), "raw_rows": raw_rows,
           "removed_duplicates": int(duplicates.sum()), "conflicting_rows": len(conflicts),
           **{name: len(rows) for name, rows in parts.items()}}).to_csv(out / "data_audit.csv")

x = finite(df[features])
y = (df["Label"] != "BENIGN").astype(int)
constant = [c for c in features if c != "Destination Port" and x.loc[train, c].nunique() <= 1]
eligible = [c for c in features if c not in constant + ["Destination Port", "Fwd Header Length.1"]]
values = x.loc[train, "Total Length of Fwd Packets"].dropna()
assert values.min() >= 0
logged = np.log1p(values)
logs = ["Total Length of Fwd Packets"] if abs(logged.skew()) < abs(values.skew()) else []
pd.Series({"raw_skew": values.skew(), "log1p_skew": logged.skew(),
           "keep_log1p": bool(logs)}).to_csv(out / "log_decision.csv")

blocks = []
for name, columns in [("numeric", [c for c in eligible if c not in logs]),
                       ("log", [c for c in eligible if c in logs])]:
    steps = [SimpleImputer(strategy="median", keep_empty_features=True)]
    if name == "log":
        steps.append(FunctionTransformer(np.log1p, feature_names_out="one-to-one"))
    blocks.append((name, make_pipeline(*steps, StandardScaler()), columns))
blocks.append(("port", PortEncoder(), ["Destination Port"]))
prep = ColumnTransformer(blocks, sparse_threshold=1)
x_train = prep.fit_transform(x.loc[train])
x_val = prep.transform(x.loc[val])
x_test = prep.transform(x.loc[test])
encoded_features = prep.get_feature_names_out().tolist()

with (out / "preprocessor.pkl").open("wb") as file:
    cloudpickle.dump(prep, file)
pd.Series(encoded_features, name="encoded_feature").to_csv(out / "encoded_features.csv", index=False)
for name, rows, matrix in zip(parts, parts.values(), [x_train, x_val, x_test]):
    sparse.save_npz(out / f"X_{name}.npz", matrix)
    pd.DataFrame({"row_id": rows, "binary_label": y.loc[rows].to_numpy(),
                  "multiclass_label": df.loc[rows, "Label"].to_numpy()}).to_csv(
                      out / f"y_{name}.csv", index=False)
keep = counts.index[(counts.train >= 100) & (counts.validation >= 20) & (counts.test >= 20)].tolist()
if "BENIGN" not in keep:
    keep.append("BENIGN")
counts.loc[~counts.index.isin(keep)].to_csv(out / "excluded_multiclass.csv")

attempts = []
for c in [np.inf, 1]:
    logistic = LogisticRegression(C=c, max_iter=1000, random_state=42)
    tick = time.perf_counter()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", ConvergenceWarning)
        logistic.fit(x_train, y.loc[train])
    failed = any(issubclass(w.category, ConvergenceWarning) for w in caught)
    maximum = float(abs(logistic.coef_).max())
    attempts.append({"C": str(c), "convergence_warning": failed, "max_abs_coefficient": maximum,
                     "fit_seconds": time.perf_counter() - tick, "warnings": [str(w.message) for w in caught]})
    if not failed and maximum <= 100:
        break
save_json("logistic_training.json", attempts)

candidates = [("logistic", logistic, sum(r["fit_seconds"] for r in attempts))]
for depth in [3, 5, 10, None]:
    tree = DecisionTreeClassifier(max_depth=depth, random_state=42)
    tick = time.perf_counter()
    tree.fit(x_train, y.loc[train])
    candidates.append(("tree", tree, time.perf_counter() - tick))

trials, chosen = [], {}
best = -np.inf
for name, model, seconds in candidates:
    probability = model.predict_proba(x_val)
    prediction = model.classes_[probability.argmax(axis=1)]
    balanced = balanced_accuracy_score(y.loc[val], prediction)
    row = {"model": name, "C": model.C if name == "logistic" else None,
           "max_depth": model.max_depth if name == "tree" else None,
           "validation_balanced_accuracy": balanced,
           "validation_log_loss": log_loss(y.loc[val], probability, labels=model.classes_),
           "fit_seconds": seconds}
    trials.append(row)
    if name == "logistic" or balanced > best:
        chosen[name] = (model, probability, prediction, row)
        if name == "tree":
            best = balanced
pd.DataFrame(trials).to_csv(out / "validation_candidates.csv", index=False)

scores, settings = [], {}
for name, (model, probability, prediction, row) in chosen.items():
    pipeline = Pipeline([("clean", FunctionTransformer(finite)), ("features", prep), ("classifier", model)])
    with (out / f"{name}_pipeline.pkl").open("wb") as file:
        cloudpickle.dump(pipeline, file)
    pd.DataFrame({"row_id": val, "true": y.loc[val].to_numpy(), "predicted": prediction,
                  "attack_probability": probability[:, 1]}).to_csv(
                      out / f"{name}_validation_predictions.csv", index=False)
    report = classification_report(y.loc[val], prediction, output_dict=True, zero_division=0)["1"]
    scores.append({**row, "attack_precision": report["precision"],
                   "attack_recall": report["recall"], "attack_f1": report["f1-score"]})
    if name == "logistic":
        settings[name] = {"C": "unregularized" if np.isinf(model.C) else model.C,
                          "n_iter": model.n_iter_.tolist()}
    else:
        settings[name] = {"max_depth": model.max_depth, "actual_depth": int(model.get_depth()),
                          "min_samples_leaf": model.min_samples_leaf, "number_of_leaves": int(model.get_n_leaves())}
        (out / "tree_first_two_levels.txt").write_text(
            export_text(model, feature_names=encoded_features, max_depth=1))
pd.DataFrame(scores).to_csv(out / "baseline_validation.csv", index=False)
save_json("selected_baselines.json", settings)

real_data = args.data_dir.resolve() == (root / "MachineLearningCVE").resolve()
save_json("manifest.json", {
    "status": "complete", "data_scope": "full real dataset" if real_data else "custom test data",
    "source_script": str(Path(__file__).resolve()),
    "source_script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    "seed": 42, "raw_rows": raw_rows, "retained_rows": len(df),
    "partition_sizes": {name: len(rows) for name, rows in parts.items()},
    "numerical_features": eligible, "log1p_features": logs,
    "known_training_ports": len(prep.named_transformers_["port"].ports_), "encoded_dimension": x_train.shape[1],
    "reserved_other_port": -1, "multiclass_categories": keep, "selected_baselines": settings,
    "test_predictions_computed": False, "preprocessing_fitted_on": "training only", "threads": 6,
    "versions": {"python": platform.python_version(), "sklearn": sklearn.__version__,
                 "numpy": np.__version__, "pandas": pd.__version__, "scipy": scipy.__version__},
    "elapsed_seconds": time.perf_counter() - started
})
save_json("run_status.json", {"status": "complete"})
thread_limit.restore_original_limits()
