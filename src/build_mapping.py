#!/usr/bin/env python3
"""Auto-generate ATT&CK mapping entries for GuardDuty finding types.

観測された finding type のうち mapping に無いものを、接頭辞(ThreatPurpose)->tactic
＋ キーワード->technique のルールで自動マッピングし、既存YAMLの末尾に追記する。
technique 対応は叩き台（# auto）。既存の手動エントリは書き換えない。
"""
from __future__ import annotations

import argparse
from pathlib import Path

import yaml

PREFIX_TACTIC = {
    "Recon": "reconnaissance",
    "InitialAccess": "initial-access",
    "UnauthorizedAccess": "initial-access",
    "Execution": "execution",
    "Object": "execution",
    "Persistence": "persistence",
    "PrivilegeEscalation": "privilege-escalation",
    "DefenseEvasion": "defense-evasion",
    "DefenseImpairment": "defense-evasion",
    "Stealth": "defense-evasion",
    "Policy": "defense-evasion",
    "CredentialAccess": "credential-access",
    "Discovery": "discovery",
    "PenTest": "discovery",
    "LateralMovement": "lateral-movement",
    "Collection": "collection",
    "CommandAndControl": "command-and-control",
    "Backdoor": "command-and-control",
    "Trojan": "command-and-control",
    "Behavior": "command-and-control",
    "Exfiltration": "exfiltration",
    "CryptoCurrency": "impact",
    "Impact": "impact",
    "ResourceDevelopment": "resource-development",
}

DEFAULT_TECHNIQUE = {
    "reconnaissance": ("T1595", "Active Scanning"),
    "resource-development": ("T1586", "Compromise Accounts"),
    "initial-access": ("T1078.004", "Valid Accounts: Cloud Accounts"),
    "execution": ("T1059", "Command and Scripting Interpreter"),
    "persistence": ("T1098", "Account Manipulation"),
    "privilege-escalation": ("T1548", "Abuse Elevation Control Mechanism"),
    "defense-evasion": ("T1562", "Impair Defenses"),
    "credential-access": ("T1552", "Unsecured Credentials"),
    "discovery": ("T1580", "Cloud Infrastructure Discovery"),
    "lateral-movement": ("T1021", "Remote Services"),
    "collection": ("T1530", "Data from Cloud Storage"),
    "command-and-control": ("T1071", "Application Layer Protocol"),
    "exfiltration": ("T1041", "Exfiltration Over C2 Channel"),
    "impact": ("T1496", "Resource Hijacking"),
}

KEYWORD_RULES = [
    ("BruteForce", "credential-access", "T1110", "Brute Force"),
    ("InstanceCredentialExfiltration", "credential-access", "T1552.005", "Unsecured Credentials: Cloud Instance Metadata API"),
    ("MetadataDNSRebind", "credential-access", "T1552.005", "Unsecured Credentials: Cloud Instance Metadata API"),
    ("ResourceCredentialExfiltration", "credential-access", "T1552", "Unsecured Credentials"),
    ("UnsecuredCredentials", "credential-access", "T1552", "Unsecured Credentials"),
    ("SecretsAccessed", "credential-access", "T1552.007", "Unsecured Credentials: Container API"),
    ("SensitiveFileRead", "credential-access", "T1552", "Unsecured Credentials"),
    ("DGADomainRequest", "command-and-control", "T1568.002", "Dynamic Resolution: Domain Generation Algorithms"),
    ("C&CActivity", "command-and-control", "T1071", "Application Layer Protocol"),
    ("BlackholeTraffic", "command-and-control", "T1071", "Application Layer Protocol"),
    ("UnusualDNSResolver", "command-and-control", "T1071.004", "Application Layer Protocol: DNS"),
    ("UnusualDoHActivity", "command-and-control", "T1071.004", "Application Layer Protocol: DNS"),
    ("UnusualDoTActivity", "command-and-control", "T1071.004", "Application Layer Protocol: DNS"),
    ("NetworkPortUnusual", "command-and-control", "T1571", "Non-Standard Port"),
    ("MaliciousDomainRequest", "command-and-control", "T1071", "Application Layer Protocol"),
    ("SuspiciousDomainRequest", "command-and-control", "T1071", "Application Layer Protocol"),
    ("AbusedDomainRequest", "command-and-control", "T1071", "Application Layer Protocol"),
    ("Tor", "command-and-control", "T1090.003", "Proxy: Multi-hop Proxy"),
    ("DNSDataExfiltration", "exfiltration", "T1048", "Exfiltration Over Alternative Protocol"),
    ("TransferDataToCloudAccount", "exfiltration", "T1537", "Transfer Data to Cloud Account"),
    ("TrafficVolumeUnusual", "exfiltration", "T1048", "Exfiltration Over Alternative Protocol"),
    ("DropPoint", "exfiltration", "T1041", "Exfiltration Over C2 Channel"),
    ("PhishingDomainRequest", "initial-access", "T1566", "Phishing"),
    ("DriveBySourceTraffic", "initial-access", "T1189", "Drive-by Compromise"),
    ("ExploitPublicFacingApplication", "initial-access", "T1190", "Exploit Public-Facing Application"),
    ("ExposedDashboard", "initial-access", "T1190", "Exploit Public-Facing Application"),
    ("KubeflowDashboardExposed", "initial-access", "T1190", "Exploit Public-Facing Application"),
    ("ValidAccounts", "initial-access", "T1078.004", "Valid Accounts: Cloud Accounts"),
    ("CompromisedCredentials", "initial-access", "T1078.004", "Valid Accounts: Cloud Accounts"),
    ("RootCredentialUsage", "initial-access", "T1078.004", "Valid Accounts: Cloud Accounts"),
    ("ConsoleLoginSuccess", "initial-access", "T1078.004", "Valid Accounts: Cloud Accounts"),
    ("BitcoinTool", "impact", "T1496", "Resource Hijacking"),
    ("BitcoinDomainRequest", "impact", "T1496", "Resource Hijacking"),
    ("CryptoMiner", "impact", "T1496", "Resource Hijacking"),
    ("CostHarvesting", "impact", "T1496", "Resource Hijacking"),
    ("ResourceHijacking", "impact", "T1496", "Resource Hijacking"),
    ("AnomalousModelInvocation", "impact", "T1496", "Resource Hijacking"),
    ("Spambot", "impact", "T1496", "Resource Hijacking"),
    ("DenialOfService", "impact", "T1498", "Network Denial of Service"),
    ("DataDestruction", "impact", "T1485", "Data Destruction"),
    ("AnomalousBehavior.Delete", "impact", "T1485", "Data Destruction"),
    ("AnomalousBehavior.Drop", "impact", "T1485", "Data Destruction"),
    ("AnomalousBehavior.Write", "impact", "T1565", "Data Manipulation"),
    ("AnomalousBehavior.Permission", "impact", "T1565", "Data Manipulation"),
    ("PromptInjection", "impact", "T1565", "Data Manipulation"),
    ("Portscan", "discovery", "T1046", "Network Service Discovery"),
    ("PortProbe", "discovery", "T1046", "Network Service Discovery"),
    ("PortSweep", "discovery", "T1046", "Network Service Discovery"),
    ("PermissionChecked", "discovery", "T1069", "Permission Groups Discovery"),
    ("ReverseShell", "execution", "T1059", "Command and Scripting Interpreter"),
    ("MaliciousFileExecuted", "execution", "T1059", "Command and Scripting Interpreter"),
    ("NewBinaryExecuted", "execution", "T1059", "Command and Scripting Interpreter"),
    ("SuspiciousShellCreated", "execution", "T1059", "Command and Scripting Interpreter"),
    ("SuspiciousTool", "execution", "T1059", "Command and Scripting Interpreter"),
    ("CommandAndScriptingInterpreter", "execution", "T1059", "Command and Scripting Interpreter"),
    ("NewLibraryLoaded", "execution", "T1129", "Shared Modules"),
    ("ExecInKubeSystemPod", "execution", "T1609", "Container Administration Command"),
    ("ExecInPod", "execution", "T1609", "Container Administration Command"),
    ("WorkloadDeployed", "execution", "T1610", "Deploy Container"),
    ("MaliciousFile", "execution", "T1204", "User Execution"),
    ("SuspiciousFile", "execution", "T1204", "User Execution"),
    ("FilelessExecution", "defense-evasion", "T1620", "Reflective Code Loading"),
    ("ProcessInjection", "defense-evasion", "T1055", "Process Injection"),
    ("PtraceAntiDebugging", "defense-evasion", "T1622", "Debugger Evasion"),
    ("KernelModuleLoaded", "defense-evasion", "T1014", "Rootkit"),
    ("LoggingDisabled", "defense-evasion", "T1562.008", "Impair Defenses: Disable or Modify Cloud Logs"),
    ("DisableOrModifyTools", "defense-evasion", "T1562.001", "Impair Defenses: Disable or Modify Tools"),
    ("ModifyCloudResourceHierarchy", "defense-evasion", "T1578", "Modify Cloud Compute Infrastructure"),
    ("PasswordPolicyChange", "defense-evasion", "T1562", "Impair Defenses"),
    ("ElevationToRoot", "privilege-escalation", "T1548", "Abuse Elevation Control Mechanism"),
    ("RuncContainerEscape", "privilege-escalation", "T1611", "Escape to Host"),
    ("ContainerMountsHostDirectory", "privilege-escalation", "T1611", "Escape to Host"),
    ("ContainerWithSensitiveMount", "privilege-escalation", "T1611", "Escape to Host"),
    ("DockerSocketAccessed", "privilege-escalation", "T1611", "Escape to Host"),
    ("PrivilegedContainer", "privilege-escalation", "T1611", "Escape to Host"),
    ("CGroupsReleaseAgentModified", "privilege-escalation", "T1611", "Escape to Host"),
    ("UserfaultfdUsage", "privilege-escalation", "T1068", "Exploitation for Privilege Escalation"),
    ("RoleBindingCreated", "privilege-escalation", "T1098", "Account Manipulation"),
    ("RoleCreated", "privilege-escalation", "T1098", "Account Manipulation"),
    ("BootOrLogonInitializationScripts", "persistence", "T1037", "Boot or Logon Initialization Scripts"),
    ("ExternalRemoteServices", "persistence", "T1133", "External Remote Services"),
    ("AccountManipulation", "persistence", "T1098", "Account Manipulation"),
    ("RemoteServices", "lateral-movement", "T1021", "Remote Services"),
    ("CompromiseAccounts", "resource-development", "T1586", "Compromise Accounts"),
    ("BucketAnonymousAccessGranted", "collection", "T1530", "Data from Cloud Storage"),
    ("BucketPublicAccessGranted", "collection", "T1530", "Data from Cloud Storage"),
    ("AnonymousAccessGranted", "collection", "T1530", "Data from Cloud Storage"),
    ("BlockPublicAccessDisabled", "collection", "T1530", "Data from Cloud Storage"),
]

SKIP_PREFIXES = {"AttackSequence"}


def classify(finding_type):
    prefix = finding_type.split(":", 1)[0]
    if prefix in SKIP_PREFIXES:
        return None
    tactic = PREFIX_TACTIC.get(prefix)
    if not tactic:
        return None
    tid, tname = DEFAULT_TECHNIQUE[tactic]
    for kw, k_tactic, k_tid, k_tname in KEYWORD_RULES:
        if kw in finding_type:
            return k_tactic, k_tid, k_tname
    return tactic, tid, tname


def read_observed(path):
    types = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            types.append(line)
    return types


def read_mapped(path):
    if not Path(path).exists():
        return set()
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return {f["finding_type"] for f in data.get("findings", [])}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--covered", default="output/covered.txt")
    ap.add_argument("--mapping", default="mappings/guardduty_attack_mapping.yaml")
    args = ap.parse_args()

    observed = read_observed(args.covered)
    mapped = read_mapped(args.mapping)

    new_types = [t for t in dict.fromkeys(observed) if t not in mapped]
    added, skipped = [], []
    lines = ["", "  # ===== auto-generated (要確認): build_mapping.py の叩き台 ====="]
    for ft in sorted(new_types):
        r = classify(ft)
        if not r:
            skipped.append(ft)
            continue
        tactic, tid, tname = r
        lines.append(f"  - finding_type: {ft}")
        lines.append(f"    tactic: {tactic}")
        lines.append(f"    technique_id: {tid}")
        lines.append(f'    technique_name: "{tname}"  # auto')
        added.append(ft)

    if added:
        with open(args.mapping, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    print(f"observed        : {len(set(observed))}")
    print(f"already mapped  : {len(mapped)}")
    print(f"auto-added      : {len(added)}")
    if skipped:
        print(f"skipped (meta)  : {len(skipped)} -> {', '.join(skipped)}")


if __name__ == "__main__":
    main()
