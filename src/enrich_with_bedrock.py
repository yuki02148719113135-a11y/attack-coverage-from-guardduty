#!/usr/bin/env python3
"""GuardDuty finding を Bedrock(Claude) に渡し、ATT&CK 対応と初動手順を JSON で返す。

attack-coverage-from-guardduty の続き。静的キーワードマッピング（build_mapping.py）の
"# auto" を、LLM の根拠つき判定で上書き／補強する「トリアージ補助」レイヤー。

出力スキーマ（1 finding あたり）:
    {
      "finding_type": "...",
      "attack": {"tactic","technique_id","technique_name","confidence"},
      "triage_steps": ["①...", "②...", ...],
      "rationale": "なぜこの TTP と判断したか",
      "source": "bedrock" | "mock"
    }

使い方:
    # Bedrock 未設定でも動く（仕組み確認・課金ゼロ）
    python src/enrich_with_bedrock.py --input examples/sample_findings.json --mock

    # 本番（要 boto3 / Bedrock 権限。東京リージョン）
    AWS_PROFILE=udemy python src/enrich_with_bedrock.py \
        --input examples/sample_findings.json --region ap-northeast-1

入力は「1 finding の JSON」または「finding の配列」。GuardDuty の finding JSON を
そのまま渡せる（Type フィールドを finding_type として使う）。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DEFAULT_MODEL = "jp.anthropic.claude-sonnet-4-6"

# --- 出力スキーマ（Bedrock の tool-use と mock で共有） ---------------------
OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "tactic": {"type": "string", "description": "ATT&CK tactic の shortname（例: credential-access）"},
        "technique_id": {"type": "string", "description": "ATT&CK technique ID（例: T1552.005）"},
        "technique_name": {"type": "string"},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "triage_steps": {
            "type": "array",
            "items": {"type": "string"},
            "description": "初動対応の具体手順を順番に。AWS の操作を含める。",
        },
        "rationale": {"type": "string", "description": "なぜこの TTP と判断したかの短い根拠"},
    },
    "required": ["tactic", "technique_id", "technique_name", "confidence", "triage_steps", "rationale"],
}

SYSTEM = (
    "あなたは AWS のクラウドセキュリティアナリスト。GuardDuty の finding を 1 件受け取り、"
    "MITRE ATT&CK の tactic/technique に対応づけ、初動対応（トリアージ）手順を示す。"
    "推測が混じる場合は confidence を下げる。手順は AWS の具体操作（該当リソースの隔離、"
    "認証情報の失効、スナップショット取得、ログ確認など）で書く。"
)


# --- mock（Bedrock なしで同じ形の出力を返す） ------------------------------
PREFIX_TACTIC = {
    "Recon": ("reconnaissance", "T1595", "Active Scanning"),
    "UnauthorizedAccess": ("initial-access", "T1078.004", "Valid Accounts: Cloud Accounts"),
    "InitialAccess": ("initial-access", "T1078.004", "Valid Accounts: Cloud Accounts"),
    "CredentialAccess": ("credential-access", "T1552", "Unsecured Credentials"),
    "Execution": ("execution", "T1204", "User Execution"),
    "Persistence": ("persistence", "T1098", "Account Manipulation"),
    "PrivilegeEscalation": ("privilege-escalation", "T1548", "Abuse Elevation Control Mechanism"),
    "DefenseEvasion": ("defense-evasion", "T1562", "Impair Defenses"),
    "DefenseImpairment": ("defense-evasion", "T1562.001", "Impair Defenses: Disable or Modify Tools"),
    "Stealth": ("defense-evasion", "T1562.008", "Impair Defenses: Disable or Modify Cloud Logs"),
    "Discovery": ("discovery", "T1580", "Cloud Infrastructure Discovery"),
    "LateralMovement": ("lateral-movement", "T1021", "Remote Services"),
    "Backdoor": ("command-and-control", "T1071", "Application Layer Protocol"),
    "Trojan": ("command-and-control", "T1071", "Application Layer Protocol"),
    "CommandAndControl": ("command-and-control", "T1071", "Application Layer Protocol"),
    "CryptoCurrency": ("impact", "T1496", "Resource Hijacking"),
    "Impact": ("impact", "T1496", "Resource Hijacking"),
    "Exfiltration": ("exfiltration", "T1537", "Transfer Data to Cloud Account"),
    "ResourceDevelopment": ("resource-development", "T1586", "Compromise Accounts"),
}

TRIAGE_BY_TACTIC = {
    "credential-access": [
        "①該当 IAM プリンシパルのアクセスキーを無効化（deactivate）",
        "②CloudTrail で当該キーの直近アクティビティを確認",
        "③影響範囲の確認後、キーをローテーション",
    ],
    "initial-access": [
        "①該当アカウント/キーのアクティビティを CloudTrail で確認",
        "②不審な送信元IPからのアクセスを特定し、必要なら SCP/条件付きポリシーで遮断",
        "③MFA 強制・パスワードリセット",
    ],
    "impact": [
        "①該当 EC2 を隔離用 SG に付け替え（アウトバウンド遮断）",
        "②EBS スナップショットを取得して保全",
        "③課金急増の有無を Cost Explorer で確認、必要ならインスタンス停止",
    ],
    "defense-evasion": [
        "①CloudTrail/ログ設定の変更内容を確認し、無効化されていれば再有効化",
        "②変更を行ったプリンシパルを特定",
        "③該当プリンシパルの権限を一時縮小",
    ],
    "exfiltration": [
        "①該当リソースの送信先を VPC Flow Logs で確認",
        "②該当 SG/NACL で外向き通信を遮断",
        "③持ち出し対象データの範囲を特定",
    ],
}
DEFAULT_TRIAGE = [
    "①該当リソースを隔離（SG 付け替え等）",
    "②CloudTrail / 関連ログで操作主体と時系列を確認",
    "③影響範囲を特定し、認証情報の失効・スナップショット保全を実施",
]


def mock_enrich(finding_type: str) -> dict:
    prefix = finding_type.split(":", 1)[0]
    tactic, tid, tname = PREFIX_TACTIC.get(prefix, ("impact", "T1496", "Resource Hijacking"))
    return {
        "tactic": tactic,
        "technique_id": tid,
        "technique_name": tname,
        "confidence": "low",
        "triage_steps": TRIAGE_BY_TACTIC.get(tactic, DEFAULT_TRIAGE),
        "rationale": f"[mock] ThreatPurpose 接頭辞 '{prefix}' から {tactic} と判定（Bedrock 未使用の既定値）",
    }


# --- Bedrock 本番 ---------------------------------------------------------
def build_prompt(finding: dict) -> str:
    return (
        "次の GuardDuty finding を分析し、record_attack_triage ツールで結果を返してください。\n\n"
        "GuardDuty finding (JSON):\n"
        f"{json.dumps(finding, ensure_ascii=False, indent=2)}"
    )


def bedrock_enrich(finding: dict, model: str, region: str) -> dict:
    import boto3  # 遅延 import

    client = boto3.client("bedrock-runtime", region_name=region)
    tool = {
        "toolSpec": {
            "name": "record_attack_triage",
            "description": "finding の ATT&CK 対応と初動手順を記録する",
            "inputSchema": {"json": OUTPUT_SCHEMA},
        }
    }
    resp = client.converse(
        modelId=model,
        system=[{"text": SYSTEM}],
        messages=[{"role": "user", "content": [{"text": build_prompt(finding)}]}],
        toolConfig={"tools": [tool], "toolChoice": {"tool": {"name": "record_attack_triage"}}},
        inferenceConfig={"maxTokens": 1024, "temperature": 0},
    )
    for block in resp["output"]["message"]["content"]:
        if "toolUse" in block:
            return block["toolUse"]["input"]
    # フォールバック: 本文から JSON を拾う
    for block in resp["output"]["message"]["content"]:
        if "text" in block:
            txt = block["text"]
            s, e = txt.find("{"), txt.rfind("}")
            if s != -1 and e != -1:
                return json.loads(txt[s : e + 1])
    raise RuntimeError("Bedrock 応答から構造化出力を取得できませんでした")


# --- 検証 -----------------------------------------------------------------
def validate(rec: dict) -> list[str]:
    errs = []
    for k in OUTPUT_SCHEMA["required"]:
        if k not in rec:
            errs.append(f"missing:{k}")
    if "confidence" in rec and rec["confidence"] not in ("high", "medium", "low"):
        errs.append(f"bad confidence:{rec.get('confidence')}")
    if "triage_steps" in rec and not isinstance(rec["triage_steps"], list):
        errs.append("triage_steps not a list")
    return errs


def finding_type_of(finding) -> str:
    if isinstance(finding, str):
        return finding
    return finding.get("Type") or finding.get("finding_type") or finding.get("type") or "UNKNOWN"


def load_findings(path: str):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "Findings" in data:  # get-findings 形式
        data = data["Findings"]
    if isinstance(data, dict):
        data = [data]
    return data


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", required=True, help="finding の JSON（単体 or 配列 or {Findings:[...]}）")
    ap.add_argument("--mock", action="store_true", help="Bedrock を呼ばず既定値で出力（課金ゼロ・確認用）")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--region", default="ap-northeast-1")
    ap.add_argument("--out", default="output/enriched.json")
    args = ap.parse_args()

    findings = load_findings(args.input)
    results, n_err = [], 0
    for f in findings:
        ft = finding_type_of(f)
        finding_obj = f if isinstance(f, dict) else {"Type": ft}
        try:
            rec = mock_enrich(ft) if args.mock else bedrock_enrich(finding_obj, args.model, args.region)
            rec["source"] = "mock" if args.mock else "bedrock"
        except Exception as e:  # noqa: BLE001
            print(f"  [skip] {ft}: {e}", file=sys.stderr)
            n_err += 1
            continue
        errs = validate(rec)
        if errs:
            print(f"  [warn] {ft}: {', '.join(errs)}", file=sys.stderr)
        out = {"finding_type": ft, "attack": {
            "tactic": rec.get("tactic"), "technique_id": rec.get("technique_id"),
            "technique_name": rec.get("technique_name"), "confidence": rec.get("confidence"),
        }, "triage_steps": rec.get("triage_steps", []), "rationale": rec.get("rationale", ""),
            "source": rec["source"]}
        results.append(out)

    outp = Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Wrote {outp}")
    print(f"  findings in : {len(findings)}")
    print(f"  enriched    : {len(results)}")
    print(f"  errors      : {n_err}")
    print(f"  mode        : {'mock' if args.mock else 'bedrock:' + args.model}")


if __name__ == "__main__":
    main()
