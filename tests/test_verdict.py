from vtscanner.config import VerdictConfig
from vtscanner.verdict import (
    Classifier,
    KeywordSet,
    Level,
    Verdict,
    classify_defender,
    combine,
    tokens,
)
from vtscanner.vtclient import FileReport

SHA = "b" * 64
C = Classifier(VerdictConfig())
RELIABLE = VerdictConfig().reliable_engines


def report(
    mal, sus=0, total=70, labels=(), names=(), categories=(), label="", engines=None, category="malicious"
):
    """Por defecto, las detecciones vienen de antivirus de referencia."""
    engines = list(engines or RELIABLE)
    detections = {
        (engines[i] if i < len(engines) else f"Motor{i}"): (category, text) for i, text in enumerate(labels)
    }
    return FileReport(SHA, mal, sus, total, detections, label, list(categories), list(names))


CRACK_LABELS = [
    "HackTool:Win32/Crack", "Riskware.Crack", "not-a-virus:HEUR:RiskTool.Win32.Crack.gen",
    "Win32:Crack-AB [PUP]", "Keygen", "HackTool.Patcher", "PUA:Win32/Presenoker",
    "Program:Win32/Contebrew.A!ml", "Tool.Crack", "Riskware/Crack", "HackTool.Win32.Crack.d",
    "Win64/HackTool.Crack.A", "Trojan.Crack", "Keygen.Generator", "HackKMS.A",
]


def test_clean():
    assert C.classify_report(report(0)).level == Level.CLEAN


def test_two_engines_naming_dangerous_families_is_critical():
    labels = ["HEUR:Trojan-PSW.MSIL.Stealer.gen", "Trojan.Win32.RedLine.abc"]
    verdict = C.classify_report(report(2, labels=labels))
    assert verdict.level == Level.CRITICAL
    assert "malware grave" in verdict.reason


def test_vt_classification_names_count():
    verdict = C.classify_report(
        report(2, labels=["Gen:Variant.Zusy.1", "Trojan.Generic"], names=[("lumma", 5)])
    )
    assert verdict.level == Level.CRITICAL
    assert "lumma" in verdict.reason


def test_many_crack_detections_are_capped_at_high():
    verdict = C.classify_report(report(15, labels=CRACK_LABELS))
    assert verdict.level == Level.HIGH
    assert "herramientas o software no deseado" in verdict.reason


def test_many_generic_detections_are_critical():
    labels = ["Trojan.GenericKD.1", "Gen:Variant.Razy.2", "ML.Attribute.HighConfidence"] * 4
    assert C.classify_report(report(12, labels=labels)).level == Level.CRITICAL


def test_medium_amount_of_crack_detections():
    assert C.classify_report(report(5, labels=CRACK_LABELS[:5])).level == Level.MEDIUM


def test_three_specific_detections_are_high():
    labels = ["Trojan.Win32.Swrort.a", "Win32/Swrort.A", "Trojan.Swrort"]
    assert C.classify_report(report(3, labels=labels)).level == Level.HIGH


def test_single_generic_detection_is_low():
    verdict = C.classify_report(report(1, labels=["Trojan:Win32/Wacatac.B!ml"]))
    assert verdict.level == Level.LOW
    assert "falso positivo" in verdict.reason


def test_single_specific_detection_is_medium():
    assert C.classify_report(report(1, labels=["Win32/Swrort.A"])).level == Level.MEDIUM


def test_single_dangerous_detection_is_medium():
    verdict = C.classify_report(report(1, labels=["Trojan.Win32.RedLine.x"]))
    assert verdict.level == Level.MEDIUM
    assert "redline" in verdict.reason


def test_suspicious_only():
    two = ["Suspicious.X", "Suspicious.Y"]
    assert C.classify_report(report(0, sus=2, labels=two, category="suspicious")).level == Level.MEDIUM
    assert C.classify_report(report(0, sus=1, labels=two[:1], category="suspicious")).level == Level.LOW
    minor = report(0, sus=2, labels=two, category="suspicious", engines=["Skyhigh", "Zillya"])
    assert C.classify_report(minor).level == Level.LOW


def test_detection_only_from_minor_engines_is_low():
    verdict = C.classify_report(report(1, labels=["Trojan.Swrort.Win32.1"], engines=["Zillya"]))
    assert verdict.level == Level.LOW
    assert "antivirus de referencia" in verdict.reason


def test_minor_engines_do_not_lower_higher_counts():
    labels = ["Trojan.Swrort.a", "Win32.Swrort.b", "Swrort.c"]
    assert C.classify_report(report(3, labels=labels, engines=["Zillya", "Bkav", "Jiangmin"])).level == Level.HIGH


def test_behaveslike_is_generic_and_label_is_cleaned():
    verdict = C.classify_report(
        report(1, labels=["BehavesLike.Win64.Downloader.tc"], engines=["Kaspersky"], label="downloader.")
    )
    assert verdict.level == Level.LOW
    assert verdict.label == "downloader"
    assert "con etiquetas genéricas (probable falso positivo)" in verdict.reason


def test_label_prefers_vt_then_family():
    assert C.classify_report(report(1, labels=["X"], label="trojan.foo/bar")).label == "trojan.foo/bar"
    labels = ["Trojan.Win32.RedLine.x", "HEUR:Trojan-PSW.Win32.RedLine.gen"]
    assert C.classify_report(report(2, labels=labels)).label == "redline"


def test_tokens_and_keywords():
    assert "notavirus" in tokens("not-a-virus:RiskTool.Win32")
    assert "virus" not in tokens("not-a-virus:RiskTool.Win32")
    assert KeywordSet(["rat"]).match(tokens("Separate.Generator.Strat")) is None
    assert KeywordSet(["rat"]).match(tokens("Backdoor.RAT.Agent")) == "rat"
    assert KeywordSet(["stealer"]).match(tokens("Win32.InfoStealer.A")) == "stealer"


def test_defender_names():
    assert classify_defender("Trojan:Win32/Wacatac.B!ml").level == Level.MEDIUM
    assert classify_defender("HackTool:Win32/Crack").level == Level.MEDIUM
    assert classify_defender("PUA:Win32/Presenoker").level == Level.MEDIUM
    assert classify_defender("Trojan:Win32/RedLine.AB").level == Level.CRITICAL
    assert classify_defender("Ransom:Win32/StopCrypt.A").level == Level.CRITICAL
    assert classify_defender("Behavior:Win32/Foo.A").level == Level.HIGH


def test_combine_takes_worst_and_joins_findings():
    verdict = combine(
        [Verdict(Level.LOW, "VT: poco"), Verdict(Level.CRITICAL, "Defender: grave", "X"), None]
    )
    assert verdict.level == Level.CRITICAL
    assert verdict.reason == "Defender: grave · VT: poco"
    assert verdict.label == "X"
    assert combine([Verdict(Level.CLEAN, "VT: 0 de 70")]).reason == "VT: 0 de 70"
