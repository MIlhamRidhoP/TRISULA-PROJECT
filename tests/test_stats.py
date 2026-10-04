import pytest

from trisula.stats import confusion_metrics, holm_adjust, mcnemar_test


def test_metrics_from_small_confusion_matrix():
    m = confusion_metrics(tp=3, fp=1, fn=6, tn=10)
    assert m.tpr == pytest.approx(0.333333, abs=1e-6)
    assert m.fpr == pytest.approx(0.090909, abs=1e-6)
    assert m.precision == pytest.approx(0.75)
    assert m.f1 == pytest.approx(0.461538, abs=1e-6)
    assert m.accuracy == pytest.approx(0.65)
    assert m.benchmark_score == pytest.approx(0.242424, abs=1e-6)


def test_symmetric_matrix_gives_round_numbers():
    m = confusion_metrics(tp=8, fp=2, fn=2, tn=8)
    assert (m.tpr, m.fpr, m.precision, m.accuracy) == pytest.approx((0.8, 0.2, 0.8, 0.8))
    assert m.f1 == pytest.approx(0.8)
    assert m.benchmark_score == pytest.approx(0.6)


def test_no_positive_predictions_leave_precision_and_f1_null():
    m = confusion_metrics(tp=0, fp=0, fn=5, tn=5)
    assert m.precision is None
    assert m.f1 is None
    assert (m.tpr, m.fpr, m.benchmark_score) == (0.0, 0.0, 0.0)


def test_zero_precision_and_recall_gives_null_f1():
    m = confusion_metrics(tp=0, fp=4, fn=4, tn=2)
    assert (m.precision, m.tpr) == (0.0, 0.0)
    assert m.f1 is None


def test_empty_matrix_is_all_null():
    m = confusion_metrics(0, 0, 0, 0)
    assert [m.tpr, m.fpr, m.precision, m.f1, m.accuracy, m.benchmark_score] == [None] * 6


def test_mcnemar_exact_for_few_discordant_pairs():
    # b=10, c=2: p = 2 * (C(12,0) + C(12,1) + C(12,2)) / 2^12 = 158 / 4096
    result = mcnemar_test(b=10, c=2, exact_below=25)
    assert result.method == "exact"
    assert result.statistic == 2
    assert result.p_value == pytest.approx(0.0385742, abs=1e-7)


def test_mcnemar_chi_square_with_continuity_correction():
    # (|30 - 10| - 1)^2 / 40 = 9.025, p dari tabel chi-square df=1
    result = mcnemar_test(b=30, c=10, exact_below=25)
    assert result.method == "chi2_corrected"
    assert result.statistic == pytest.approx(9.025)
    assert result.p_value == pytest.approx(0.0026631, abs=1e-6)


def test_mcnemar_switches_method_at_threshold():
    assert mcnemar_test(b=20, c=4, exact_below=25).method == "exact"
    assert mcnemar_test(b=20, c=5, exact_below=25).method == "chi2_corrected"


def test_mcnemar_with_no_discordant_pairs_is_not_significant():
    assert mcnemar_test(b=0, c=0, exact_below=25).p_value == 1.0


def test_holm_adjustment_keeps_order_monotone():
    # urut: 0.01*3=0.03, 0.03*2=0.06, 0.04*1=0.04 -> dinaikkan ke 0.06 supaya monoton
    assert holm_adjust([0.01, 0.04, 0.03], alpha=0.05) == pytest.approx([0.03, 0.06, 0.06])
