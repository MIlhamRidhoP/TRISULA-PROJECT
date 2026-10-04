from dataclasses import asdict, dataclass

from statsmodels.stats.contingency_tables import mcnemar
from statsmodels.stats.multitest import multipletests


@dataclass(frozen=True)
class ConfusionMetrics:
    tp: int
    fp: int
    fn: int
    tn: int
    tpr: float | None
    fpr: float | None
    precision: float | None
    f1: float | None
    accuracy: float | None
    benchmark_score: float | None

    def as_dict(self) -> dict:
        return asdict(self)


def _ratio(numerator: float, denominator: float) -> float | None:
    return numerator / denominator if denominator else None


def confusion_metrics(tp: int, fp: int, fn: int, tn: int) -> ConfusionMetrics:
    """Rumus DESIGN.md bagian 4.3. Penyebut nol menghasilkan None, bukan 0."""
    tpr = _ratio(tp, tp + fn)
    fpr = _ratio(fp, fp + tn)
    precision = _ratio(tp, tp + fp)
    f1 = None
    if precision is not None and tpr is not None:
        f1 = _ratio(2 * precision * tpr, precision + tpr)
    score = tpr - fpr if tpr is not None and fpr is not None else None
    return ConfusionMetrics(
        tp=tp,
        fp=fp,
        fn=fn,
        tn=tn,
        tpr=tpr,
        fpr=fpr,
        precision=precision,
        f1=f1,
        accuracy=_ratio(tp + tn, tp + fp + fn + tn),
        benchmark_score=score,
    )


def count_confusion(pairs: list[tuple[bool, bool]]) -> ConfusionMetrics:
    """`pairs` berisi (diprediksi rentan, label rentan)."""
    tp = sum(1 for predicted, actual in pairs if predicted and actual)
    fp = sum(1 for predicted, actual in pairs if predicted and not actual)
    fn = sum(1 for predicted, actual in pairs if not predicted and actual)
    tn = sum(1 for predicted, actual in pairs if not predicted and not actual)
    return confusion_metrics(tp, fp, fn, tn)


@dataclass(frozen=True)
class McNemarResult:
    b: int
    c: int
    method: str
    statistic: float
    p_value: float


def mcnemar_test(b: int, c: int, exact_below: int) -> McNemarResult:
    """Uji McNemar dari jumlah pasangan berbeda b dan c (DESIGN.md bagian 4.8).

    Versi exact binomial jika b + c < exact_below, selain itu chi-square dengan koreksi kontinuitas."""
    exact = b + c < exact_below
    bunch = mcnemar([[0, b], [c, 0]], exact=exact, correction=True)
    return McNemarResult(
        b=b,
        c=c,
        method="exact" if exact else "chi2_corrected",
        statistic=float(bunch.statistic),
        p_value=float(bunch.pvalue),
    )


def holm_adjust(p_values: list[float], alpha: float) -> list[float]:
    if not p_values:
        return []
    return [float(p) for p in multipletests(p_values, alpha=alpha, method="holm")[1]]
