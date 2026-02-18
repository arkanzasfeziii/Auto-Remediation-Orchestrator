#!/usr/bin/env python3
"""
Auto-Remediation Orchestrator
==============================
A production-grade, safety-first CLI tool for automated remediation of cloud
security misconfigurations across AWS, Azure, and GCP.

DRY-RUN by default. Never applies changes without explicit multi-step confirmation.

Author: arkanzasfeziii
License: MIT
"""

# === Imports ===

from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import sys
import textwrap
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from io import StringIO
from pathlib import Path
from typing import Any, Callable, Optional


# === Constants ===

TOOL_NAME = "Auto-Remediation Orchestrator"
TOOL_VERSION = "1.0.0"
AUTHOR = "arkanzasfeziii"

LEGAL_WARNING = """
╔══════════════════════════════════════════════════════════════════════════════════╗
║                    🔴  CRITICAL WARNING — READ BEFORE PROCEEDING  🔴             ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║  This tool can MODIFY your cloud resources when --apply is used.                 ║
║  Misuse can cause OUTAGES, DATA LOSS, PERMISSION LOCKOUTS, or SECURITY           ║
║  DEGRADATION. It is for authorized remediation of YOUR OWN environments ONLY.    ║
║                                                                                  ║
║  Unauthorized modification of cloud resources is ILLEGAL.                        ║
║                                                                                  ║
║  ✔ ALWAYS run --dry-run first and review every proposed change                   ║
║  ✔ Test in a non-production / sandbox environment before production              ║
║  ✔ Have a rollback plan ready before applying any changes                        ║
║  ✔ Use least-privilege, scoped credentials                                       ║
║  ✔ Never run --apply unattended or in CI/CD without human review                 ║
║                                                                                  ║
║  The author (arkanzasfeziii) and contributors assume NO LIABILITY for any        ║
║  damage, loss, or consequences — under ANY circumstance.                         ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

APPLY_CONFIRMATION_PHRASE = "YES I ACCEPT FULL RESPONSIBILITY"

EXAMPLES_TEXT = """
Real-World Usage Examples
─────────────────────────

# --- DRY-RUN (safe, default) ---

# Simulate all AWS remediations (no changes made)
  python autoremediation.py --provider aws --dry-run

# Simulate Azure remediations for storage resources only
  python autoremediation.py --provider azure --dry-run --resource-type storage

# Simulate GCP firewall remediation and export HTML report
  python autoremediation.py --provider gcp --dry-run --resource-type firewall --output html

# Simulate all providers and export JSON diff
  python autoremediation.py --provider all --dry-run --output json

# Filter resources by name pattern
  python autoremediation.py --provider aws --dry-run --filter "prod-*"

# --- APPLY (modifies resources — use with extreme caution) ---

# Apply AWS S3 public access blocks (requires full confirmation)
  python autoremediation.py --provider aws --apply --confirm --i-understand-risk --resource-type s3

# Apply all GCP bucket IAM remediations with verbose logging
  python autoremediation.py --provider gcp --apply --confirm --i-understand-risk --verbose

# Apply Azure NSG remediations and export a change log
  python autoremediation.py --provider azure --apply --confirm --i-understand-risk --output txt

# --- INFORMATION ---

# Print this examples list
  python autoremediation.py --examples

# Show version
  python autoremediation.py --version
"""

RATE_LIMIT_SLEEP = 0.3


# === Data Models ===

class RiskLevel(str, Enum):
    SAFE = "SAFE"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class RemediationStatus(str, Enum):
    PENDING = "PENDING"
    APPLIED = "APPLIED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    DRY_RUN = "DRY_RUN"


class Provider(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    ALL = "all"


@dataclass
class RemediationAction:
    """Describes a single remediation action to be applied or simulated."""
    rule_id: str
    title: str
    provider: str
    resource_id: str
    resource_type: str
    risk_level: RiskLevel
    description: str
    before_state: dict[str, Any]
    after_state: dict[str, Any]
    rollback_hint: str
    apply_fn: Optional[Callable[[], bool]] = field(default=None, repr=False)
    status: RemediationStatus = RemediationStatus.PENDING
    error_message: str = ""
    applied_at: str = ""


@dataclass
class RemediationReport:
    """Aggregated result of a remediation run."""
    provider: str
    mode: str  # "dry-run" or "apply"
    start_time: str
    end_time: str
    total_actions: int
    applied: int
    failed: int
    skipped: int
    dry_run: int
    actions: list[RemediationAction] = field(default_factory=list)
    posture_score_before: float = 0.0
    posture_score_after: float = 0.0


# === Utility Functions ===

def setup_logging(verbose: bool = False, debug: bool = False) -> logging.Logger:
    """Configure structured logging.

    Args:
        verbose: Enable INFO-level logging.
        debug: Enable DEBUG-level logging (overrides verbose).

    Returns:
        Configured logger instance.
    """
    level = logging.WARNING
    if verbose:
        level = logging.INFO
    if debug:
        level = logging.DEBUG

    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        level=level,
        stream=sys.stderr,
    )
    return logging.getLogger(TOOL_NAME)


def _require(package: str, pip_name: Optional[str] = None) -> Any:
    """Import a package or exit with a helpful install message."""
    import importlib
    try:
        return importlib.import_module(package)
    except ImportError:
        install = pip_name or package
        print(
            f"[ERROR] Missing dependency '{install}'. Install with: pip install {install}",
            file=sys.stderr,
        )
        sys.exit(1)


def matches_filter(name: str, pattern: Optional[str]) -> bool:
    """Check if a resource name matches a glob-style filter pattern."""
    if not pattern:
        return True
    import fnmatch
    return fnmatch.fnmatch(name.lower(), pattern.lower())


def truncate(text: str, max_len: int = 60) -> str:
    """Truncate string to max_len characters."""
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


def risk_icon(risk: RiskLevel) -> str:
    """Return a visual icon for a risk level."""
    return {"SAFE": "🟢", "MEDIUM": "🟡", "HIGH": "🔴"}[risk.value]


def diff_dict(before: dict, after: dict) -> str:
    """Produce a human-readable diff of two dicts."""
    lines = []
    all_keys = set(before) | set(after)
    for k in sorted(all_keys):
        b = before.get(k, "<absent>")
        a = after.get(k, "<absent>")
        if b != a:
            lines.append(f"  - {k}: {b!r}  →  {a!r}")
        else:
            lines.append(f"  = {k}: {b!r}")
    return "\n".join(lines) if lines else "  (no changes)"


# === Remediation Rules ===
# Each rule is a function that takes provider-specific client args and returns
# a list of RemediationAction objects (never executes apply_fn here).

# --- AWS Rules ---

def rule_aws_s3_block_public_access(
    s3_client: Any,
    name_filter: Optional[str],
    logger: logging.Logger,
) -> list[RemediationAction]:
    """Generate remediation actions to enable S3 Block Public Access.

    Args:
        s3_client: Boto3 S3 client.
        name_filter: Optional glob filter for bucket names.
        logger: Logger instance.

    Returns:
        List of RemediationAction objects.
    """
    actions: list[RemediationAction] = []

    try:
        buckets = s3_client.list_buckets().get("Buckets", [])
    except Exception as exc:
        logger.error("Failed to list S3 buckets: %s", exc)
        return []

    for bucket in buckets:
        name = bucket["Name"]
        if not matches_filter(name, name_filter):
            continue

        try:
            resp = s3_client.get_public_access_block(Bucket=name)
            cfg = resp["PublicAccessBlockConfiguration"]
        except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
            cfg = {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
        except Exception as exc:
            logger.warning("Cannot get public access block for %s: %s", name, exc)
            continue

        desired = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }

        if all(cfg.get(k) for k in desired):
            logger.info("S3 bucket %s already has full public access block.", name)
            continue

        bucket_name = name

        def apply_s3_block(bname: str = bucket_name, client: Any = s3_client) -> bool:
            client.put_public_access_block(
                Bucket=bname,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
            return True

        actions.append(RemediationAction(
            rule_id="AWS-S3-001",
            title="Enable S3 Block Public Access",
            provider="aws",
            resource_id=f"s3://{name}",
            resource_type="s3",
            risk_level=RiskLevel.SAFE,
            description=(
                f"Bucket '{name}' does not have all Block Public Access settings enabled. "
                "Enabling prevents accidental public exposure of bucket contents."
            ),
            before_state=cfg,
            after_state=desired,
            rollback_hint=(
                f"aws s3api put-public-access-block --bucket {name} "
                f"--public-access-block-configuration BlockPublicAcls=false,"
                f"IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false"
            ),
            apply_fn=apply_s3_block,
        ))
        time.sleep(RATE_LIMIT_SLEEP)

    return actions


def rule_aws_s3_enforce_sse_kms(
    s3_client: Any,
    name_filter: Optional[str],
    logger: logging.Logger,
) -> list[RemediationAction]:
    """Generate actions to enforce SSE-KMS default encryption on S3 buckets.

    Args:
        s3_client: Boto3 S3 client.
        name_filter: Optional filter.
        logger: Logger instance.

    Returns:
        List of RemediationAction objects.
    """
    actions: list[RemediationAction] = []

    try:
        buckets = s3_client.list_buckets().get("Buckets", [])
    except Exception as exc:
        logger.error("Failed to list S3 buckets for SSE-KMS check: %s", exc)
        return []

    for bucket in buckets:
        name = bucket["Name"]
        if not matches_filter(name, name_filter):
            continue

        try:
            enc = s3_client.get_bucket_encryption(Bucket=name)
            rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
            current_algo = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        except s3_client.exceptions.ServerSideEncryptionConfigurationNotFoundError:
            current_algo = "NONE"
        except Exception as exc:
            logger.warning("Cannot check encryption for bucket %s: %s", name, exc)
            continue

        if current_algo == "aws:kms":
            continue

        before = {"SSEAlgorithm": current_algo}
        after = {"SSEAlgorithm": "aws:kms"}
        bucket_name = name

        def apply_sse_kms(bname: str = bucket_name, client: Any = s3_client) -> bool:
            client.put_bucket_encryption(
                Bucket=bname,
                ServerSideEncryptionConfiguration={
                    "Rules": [{
                        "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"},
                        "BucketKeyEnabled": True,
                    }]
                },
            )
            return True

        actions.append(RemediationAction(
            rule_id="AWS-S3-002",
            title="Enforce SSE-KMS Default Encryption on S3 Bucket",
            provider="aws",
            resource_id=f"s3://{name}",
            resource_type="s3",
            risk_level=RiskLevel.SAFE,
            description=(
                f"Bucket '{name}' default encryption is '{current_algo}'. "
                "Upgrading to aws:kms ensures all new objects use KMS encryption."
            ),
            before_state=before,
            after_state=after,
            rollback_hint=(
                f"aws s3api put-bucket-encryption --bucket {name} "
                "--server-side-encryption-configuration "
                f"'{{\"Rules\":[{{\"ApplyServerSideEncryptionByDefault\":{{\"SSEAlgorithm\":\"{current_algo}\"}}}}]}}'"
            ),
            apply_fn=apply_sse_kms,
        ))
        time.sleep(RATE_LIMIT_SLEEP)

    return actions


def rule_aws_sg_remove_public_ingress(
    ec2_client: Any,
    name_filter: Optional[str],
    logger: logging.Logger,
) -> list[RemediationAction]:
    """Generate actions to remove overly permissive inbound security group rules.

    Targets rules that allow 0.0.0.0/0 on sensitive ports (22, 3389, 0-65535).

    Args:
        ec2_client: Boto3 EC2 client.
        name_filter: Optional filter.
        logger: Logger instance.

    Returns:
        List of RemediationAction objects.
    """
    SENSITIVE_PORTS = {22, 3389, 0}
    actions: list[RemediationAction] = []

    try:
        paginator = ec2_client.get_paginator("describe_security_groups")
        sgs = [sg for page in paginator.paginate() for sg in page["SecurityGroups"]]
    except Exception as exc:
        logger.error("Failed to list security groups: %s", exc)
        return []

    for sg in sgs:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", sg_id)
        if not matches_filter(sg_name, name_filter):
            continue

        bad_rules = []
        for perm in sg.get("IpPermissions", []):
            for ip_range in perm.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    from_port = perm.get("FromPort", 0)
                    to_port = perm.get("ToPort", 65535)
                    if from_port in SENSITIVE_PORTS or (from_port == 0 and to_port == 65535):
                        bad_rules.append(perm)
                        break

        if not bad_rules:
            continue

        sg_id_capture = sg_id
        bad_rules_capture = bad_rules

        def apply_sg_fix(
            _sg_id: str = sg_id_capture,
            _rules: list = bad_rules_capture,
            client: Any = ec2_client,
        ) -> bool:
            client.revoke_security_group_ingress(
                GroupId=_sg_id,
                IpPermissions=_rules,
            )
            return True

        actions.append(RemediationAction(
            rule_id="AWS-EC2-001",
            title=f"Remove Public Ingress from Security Group {sg_id}",
            provider="aws",
            resource_id=sg_id,
            resource_type="security_group",
            risk_level=RiskLevel.HIGH,
            description=(
                f"Security group '{sg_name}' ({sg_id}) has {len(bad_rules)} rule(s) allowing "
                "0.0.0.0/0 inbound on sensitive ports (SSH/RDP/all). "
                "This exposes resources to the entire internet."
            ),
            before_state={"public_ingress_rules": len(bad_rules), "sg_id": sg_id},
            after_state={"public_ingress_rules": 0, "sg_id": sg_id},
            rollback_hint=(
                f"aws ec2 authorize-security-group-ingress --group-id {sg_id} "
                "--ip-permissions '<original_rules_json>'  "
                "# Capture current rules with: "
                f"aws ec2 describe-security-groups --group-ids {sg_id}"
            ),
            apply_fn=apply_sg_fix,
        ))
        time.sleep(RATE_LIMIT_SLEEP)

    return actions


def rule_aws_iam_restrict_wildcards(
    iam_client: Any,
    name_filter: Optional[str],
    logger: logging.Logger,
) -> list[RemediationAction]:
    """Generate actions to flag and detach IAM inline policies with wildcard actions.

    Note: This generates HIGH-risk actions (detaching policies). Dry-run recommended.

    Args:
        iam_client: Boto3 IAM client.
        name_filter: Optional filter for policy/user names.
        logger: Logger instance.

    Returns:
        List of RemediationAction objects.
    """
    actions: list[RemediationAction] = []

    try:
        paginator = iam_client.get_paginator("list_users")
        users = [u for page in paginator.paginate() for u in page["Users"]]
    except Exception as exc:
        logger.error("Failed to list IAM users: %s", exc)
        return []

    for user in users:
        uname = user["UserName"]
        if not matches_filter(uname, name_filter):
            continue

        try:
            inline = iam_client.list_user_policies(UserName=uname)["PolicyNames"]
        except Exception as exc:
            logger.warning("Cannot list inline policies for %s: %s", uname, exc)
            continue

        for pname in inline:
            try:
                doc = iam_client.get_user_policy(UserName=uname, PolicyName=pname)
                import urllib.parse
                policy_doc = json.loads(
                    urllib.parse.unquote(json.dumps(doc["PolicyDocument"]))
                )
            except Exception as exc:
                logger.warning("Cannot get policy %s for user %s: %s", pname, uname, exc)
                continue

            has_wildcard = any(
                stmt.get("Effect") == "Allow"
                and (stmt.get("Action") == "*" or stmt.get("Action") == ["*"])
                for stmt in policy_doc.get("Statement", [])
            )

            if not has_wildcard:
                continue

            uname_c, pname_c = uname, pname

            def apply_detach(
                _user: str = uname_c,
                _policy: str = pname_c,
                client: Any = iam_client,
            ) -> bool:
                client.delete_user_policy(UserName=_user, PolicyName=_policy)
                return True

            actions.append(RemediationAction(
                rule_id="AWS-IAM-001",
                title=f"Remove Wildcard Inline IAM Policy '{pname}' from User '{uname}'",
                provider="aws",
                resource_id=f"iam::user/{uname}",
                resource_type="iam_user",
                risk_level=RiskLevel.HIGH,
                description=(
                    f"User '{uname}' has inline policy '{pname}' with Action: '*'. "
                    "This grants unrestricted access to all AWS services and violates least privilege."
                ),
                before_state={"inline_policy": pname, "has_wildcard_action": True},
                after_state={"inline_policy": pname, "has_wildcard_action": False, "policy_deleted": True},
                rollback_hint=(
                    f"aws iam put-user-policy --user-name {uname} --policy-name {pname} "
                    "--policy-document '<original_policy_json>'  "
                    "# Capture first with: "
                    f"aws iam get-user-policy --user-name {uname} --policy-name {pname}"
                ),
                apply_fn=apply_detach,
            ))
        time.sleep(RATE_LIMIT_SLEEP)

    return actions


# --- Azure Rules ---

def rule_azure_storage_block_public(
    storage_client: Any,
    subscription_id: str,
    name_filter: Optional[str],
    logger: logging.Logger,
) -> list[RemediationAction]:
    """Generate actions to disable public blob access on Azure Storage Accounts.

    Args:
        storage_client: Azure StorageManagementClient.
        subscription_id: Azure subscription ID.
        name_filter: Optional filter for account names.
        logger: Logger instance.

    Returns:
        List of RemediationAction objects.
    """
    actions: list[RemediationAction] = []

    try:
        accounts = list(storage_client.storage_accounts.list())
    except Exception as exc:
        logger.error("Failed to list Azure storage accounts: %s", exc)
        return []

    for account in accounts:
        aname = account.name or "unknown"
        if not matches_filter(aname, name_filter):
            continue

        allow_public = getattr(account, "allow_blob_public_access", True)
        if allow_public is False:
            continue

        rg = account.id.split("/resourceGroups/")[1].split("/")[0] if account.id else ""
        aname_c, rg_c = aname, rg

        def apply_block(
            _name: str = aname_c,
            _rg: str = rg_c,
            client: Any = storage_client,
        ) -> bool:
            from azure.mgmt.storage.models import StorageAccountUpdateParameters
            client.storage_accounts.update(
                _rg, _name,
                StorageAccountUpdateParameters(allow_blob_public_access=False),
            )
            return True

        actions.append(RemediationAction(
            rule_id="AZ-ST-001",
            title=f"Disable Public Blob Access on Storage Account '{aname}'",
            provider="azure",
            resource_id=account.id or aname,
            resource_type="storage_account",
            risk_level=RiskLevel.SAFE,
            description=(
                f"Storage account '{aname}' allows public blob access. "
                "Disabling this prevents anonymous reads of container data."
            ),
            before_state={"allow_blob_public_access": True},
            after_state={"allow_blob_public_access": False},
            rollback_hint=(
                f"az storage account update --name {aname} --resource-group {rg} "
                "--allow-blob-public-access true"
            ),
            apply_fn=apply_block,
        ))

    return actions


def rule_azure_nsg_restrict_inbound(
    network_client: Any,
    name_filter: Optional[str],
    logger: logging.Logger,
) -> list[RemediationAction]:
    """Generate actions to restrict overly permissive Azure NSG inbound rules.

    Args:
        network_client: Azure NetworkManagementClient.
        name_filter: Optional filter.
        logger: Logger instance.

    Returns:
        List of RemediationAction objects.
    """
    RISKY_PORTS = {"22", "3389", "*"}
    actions: list[RemediationAction] = []

    try:
        nsgs = list(network_client.network_security_groups.list_all())
    except Exception as exc:
        logger.error("Failed to list Azure NSGs: %s", exc)
        return []

    for nsg in nsgs:
        nsg_name = nsg.name or "unknown"
        if not matches_filter(nsg_name, name_filter):
            continue

        for rule in nsg.security_rules or []:
            if (
                rule.direction == "Inbound"
                and rule.access == "Allow"
                and rule.source_address_prefix in ("*", "Internet", "0.0.0.0/0")
                and str(rule.destination_port_range) in RISKY_PORTS
            ):
                rg = nsg.id.split("/resourceGroups/")[1].split("/")[0] if nsg.id else ""
                nsg_name_c, rule_name_c, rg_c = nsg.name, rule.name, rg
                nsg_id = nsg.id or nsg_name

                def apply_nsg_deny(
                    _nsg: str = nsg_name_c,
                    _rule: str = rule_name_c,
                    _rg: str = rg_c,
                    client: Any = network_client,
                ) -> bool:
                    existing = client.security_rules.get(_rg, _nsg, _rule)
                    existing.access = "Deny"
                    client.security_rules.begin_create_or_update(
                        _rg, _nsg, _rule, existing
                    ).result()
                    return True

                actions.append(RemediationAction(
                    rule_id="AZ-NSG-001",
                    title=f"Restrict NSG Rule '{rule.name}' in '{nsg_name}'",
                    provider="azure",
                    resource_id=nsg_id,
                    resource_type="nsg",
                    risk_level=RiskLevel.HIGH,
                    description=(
                        f"NSG '{nsg_name}' has rule '{rule.name}' allowing inbound "
                        f"{rule.destination_port_range} from ANY source. "
                        "This exposes resources to the internet."
                    ),
                    before_state={"access": "Allow", "source": rule.source_address_prefix, "port": rule.destination_port_range},
                    after_state={"access": "Deny", "source": rule.source_address_prefix, "port": rule.destination_port_range},
                    rollback_hint=(
                        f"az network nsg rule update --resource-group {rg} "
                        f"--nsg-name {nsg_name} --name {rule.name} --access Allow"
                    ),
                    apply_fn=apply_nsg_deny,
                ))

    return actions


# --- GCP Rules ---

def rule_gcp_bucket_remove_public_iam(
    storage_client: Any,
    project: str,
    name_filter: Optional[str],
    logger: logging.Logger,
) -> list[RemediationAction]:
    """Generate actions to remove allUsers/allAuthenticatedUsers from GCS bucket IAM.

    Args:
        storage_client: GCS storage.Client instance.
        project: GCP project ID.
        name_filter: Optional filter.
        logger: Logger instance.

    Returns:
        List of RemediationAction objects.
    """
    PUBLIC_MEMBERS = {"allUsers", "allAuthenticatedUsers"}
    actions: list[RemediationAction] = []

    try:
        buckets = list(storage_client.list_buckets(project=project))
    except Exception as exc:
        logger.error("Failed to list GCS buckets: %s", exc)
        return []

    for bucket in buckets:
        bname = bucket.name
        if not matches_filter(bname, name_filter):
            continue

        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
        except Exception as exc:
            logger.warning("Cannot get IAM policy for bucket %s: %s", bname, exc)
            continue

        public_bindings = []
        for binding in policy.bindings:
            members_to_remove = [m for m in binding.get("members", []) if m in PUBLIC_MEMBERS]
            if members_to_remove:
                public_bindings.append({
                    "role": binding["role"],
                    "members": members_to_remove,
                })

        if not public_bindings:
            continue

        bname_c = bname

        def apply_gcp_iam_fix(
            _bname: str = bname_c,
            client: Any = storage_client,
            _bindings: list = public_bindings,
        ) -> bool:
            b = client.bucket(_bname)
            pol = b.get_iam_policy(requested_policy_version=3)
            for binding in pol.bindings:
                for bd in _bindings:
                    if binding.get("role") == bd["role"]:
                        binding["members"] = {
                            m for m in binding.get("members", set())
                            if m not in PUBLIC_MEMBERS
                        }
            b.set_iam_policy(pol)
            return True

        actions.append(RemediationAction(
            rule_id="GCP-GCS-001",
            title=f"Remove Public IAM Members from GCS Bucket '{bname}'",
            provider="gcp",
            resource_id=f"gs://{bname}",
            resource_type="gcs_bucket",
            risk_level=RiskLevel.SAFE,
            description=(
                f"Bucket '{bname}' has IAM bindings for allUsers or allAuthenticatedUsers. "
                "This makes bucket data publicly accessible. Removing these bindings "
                "enforces private access control."
            ),
            before_state={"public_bindings": public_bindings},
            after_state={"public_bindings": []},
            rollback_hint=(
                f"# Re-add public members if needed:\n"
                + "\n".join(
                    f"gsutil iam ch {m}:{bd['role'].split('/')[-1]} gs://{bname}"
                    for bd in public_bindings
                    for m in bd["members"]
                )
            ),
            apply_fn=apply_gcp_iam_fix,
        ))
        time.sleep(RATE_LIMIT_SLEEP)

    return actions


def rule_gcp_firewall_restrict_ingress(
    compute_client: Any,
    project: str,
    name_filter: Optional[str],
    logger: logging.Logger,
) -> list[RemediationAction]:
    """Generate actions to disable overly permissive GCP firewall ingress rules.

    Args:
        compute_client: GCP compute_v1.FirewallsClient instance.
        project: GCP project ID.
        name_filter: Optional filter.
        logger: Logger instance.

    Returns:
        List of RemediationAction objects.
    """
    actions: list[RemediationAction] = []

    try:
        firewalls = list(compute_client.list(project=project))
    except Exception as exc:
        logger.error("Failed to list GCP firewall rules: %s", exc)
        return []

    for fw in firewalls:
        fw_name = fw.name
        if not matches_filter(fw_name, name_filter):
            continue

        is_ingress = fw.direction == "INGRESS"
        has_public_src = "0.0.0.0/0" in (fw.source_ranges or [])
        has_risky_ports = any(
            allowed.ports and any(p in ("22", "3389", "0-65535") for p in allowed.ports)
            for allowed in (fw.allowed or [])
        )

        if not (is_ingress and has_public_src and has_risky_ports):
            continue

        fw_name_c = fw_name

        def apply_fw_disable(
            _fname: str = fw_name_c,
            _proj: str = project,
            client: Any = compute_client,
        ) -> bool:
            from google.cloud import compute_v1
            request = compute_v1.PatchFirewallRequest(
                project=_proj,
                firewall=_fname,
                firewall_resource=compute_v1.Firewall(disabled=True),
            )
            client.patch(request=request).result()
            return True

        actions.append(RemediationAction(
            rule_id="GCP-FW-001",
            title=f"Disable Permissive Firewall Rule '{fw_name}'",
            provider="gcp",
            resource_id=fw_name,
            resource_type="firewall",
            risk_level=RiskLevel.HIGH,
            description=(
                f"Firewall rule '{fw_name}' allows inbound traffic from 0.0.0.0/0 on "
                "sensitive ports (SSH/RDP/all). This exposes compute instances to the internet."
            ),
            before_state={"disabled": False, "source_ranges": list(fw.source_ranges or [])},
            after_state={"disabled": True},
            rollback_hint=(
                f"gcloud compute firewall-rules update {fw_name} --no-disabled "
                f"--project {project}"
            ),
            apply_fn=apply_fw_disable,
        ))
        time.sleep(RATE_LIMIT_SLEEP)

    return actions


def rule_gcp_bucket_enforce_uniform_access(
    storage_client: Any,
    project: str,
    name_filter: Optional[str],
    logger: logging.Logger,
) -> list[RemediationAction]:
    """Generate actions to enforce uniform bucket-level access on GCS buckets.

    Args:
        storage_client: GCS storage.Client instance.
        project: GCP project ID.
        name_filter: Optional filter.
        logger: Logger instance.

    Returns:
        List of RemediationAction objects.
    """
    actions: list[RemediationAction] = []

    try:
        buckets = list(storage_client.list_buckets(project=project))
    except Exception as exc:
        logger.error("Failed to list GCS buckets for uniform access check: %s", exc)
        return []

    for bucket in buckets:
        bname = bucket.name
        if not matches_filter(bname, name_filter):
            continue

        if bucket.iam_configuration.uniform_bucket_level_access_enabled:
            continue

        bname_c = bname

        def apply_uniform(
            _bname: str = bname_c,
            client: Any = storage_client,
        ) -> bool:
            b = client.bucket(_bname)
            b.iam_configuration.uniform_bucket_level_access_enabled = True
            b.patch()
            return True

        actions.append(RemediationAction(
            rule_id="GCP-GCS-002",
            title=f"Enforce Uniform Bucket-Level Access on '{bname}'",
            provider="gcp",
            resource_id=f"gs://{bname}",
            resource_type="gcs_bucket",
            risk_level=RiskLevel.MEDIUM,
            description=(
                f"Bucket '{bname}' does not have uniform bucket-level access enabled. "
                "Object ACLs can override IAM policies, creating inconsistent access controls."
            ),
            before_state={"uniform_bucket_level_access_enabled": False},
            after_state={"uniform_bucket_level_access_enabled": True},
            rollback_hint=(
                f"gsutil uniformbucketlevelaccess set off gs://{bname}\n"
                "# Note: Cannot disable if bucket has been uniform for >90 days."
            ),
            apply_fn=apply_uniform,
        ))
        time.sleep(RATE_LIMIT_SLEEP)

    return actions


# === Provider Clients ===

def gather_aws_actions(
    vault_id: Optional[str],
    resource_type: str,
    name_filter: Optional[str],
    logger: logging.Logger,
) -> list[RemediationAction]:
    """Gather all applicable AWS remediation actions.

    Args:
        vault_id: Unused for AWS (present for interface consistency).
        resource_type: Resource type filter (all/s3/iam/security_group).
        name_filter: Glob filter for resource names.
        logger: Logger instance.

    Returns:
        List of RemediationAction objects.
    """
    boto3 = _require("boto3")
    from botocore.config import Config
    cfg = Config(read_timeout=30, connect_timeout=30)

    actions: list[RemediationAction] = []
    rt = resource_type.lower()

    if rt in ("all", "s3"):
        try:
            s3 = boto3.client("s3", config=cfg)
            actions.extend(rule_aws_s3_block_public_access(s3, name_filter, logger))
            actions.extend(rule_aws_s3_enforce_sse_kms(s3, name_filter, logger))
        except Exception as exc:
            logger.error("AWS S3 client initialization failed: %s", exc)

    if rt in ("all", "security_group", "sg", "ec2"):
        try:
            ec2 = boto3.client("ec2", config=cfg)
            actions.extend(rule_aws_sg_remove_public_ingress(ec2, name_filter, logger))
        except Exception as exc:
            logger.error("AWS EC2 client initialization failed: %s", exc)

    if rt in ("all", "iam"):
        try:
            iam = boto3.client("iam", config=cfg)
            actions.extend(rule_aws_iam_restrict_wildcards(iam, name_filter, logger))
        except Exception as exc:
            logger.error("AWS IAM client initialization failed: %s", exc)

    return actions


def gather_azure_actions(
    vault_id: Optional[str],
    resource_type: str,
    name_filter: Optional[str],
    logger: logging.Logger,
) -> list[RemediationAction]:
    """Gather all applicable Azure remediation actions.

    Args:
        vault_id: Unused (interface consistency).
        resource_type: Resource type filter.
        name_filter: Glob filter.
        logger: Logger instance.

    Returns:
        List of RemediationAction objects.
    """
    try:
        azure_identity = _require("azure.identity", "azure-identity")
        credential = azure_identity.DefaultAzureCredential()
    except SystemExit:
        return []

    actions: list[RemediationAction] = []
    rt = resource_type.lower()

    sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    if not sub_id:
        try:
            sub_mod = _require("azure.mgmt.subscription", "azure-mgmt-subscription")
            sub_client = sub_mod.SubscriptionClient(credential)
            subs = list(sub_client.subscriptions.list())
            sub_id = subs[0].subscription_id if subs else ""
        except Exception as exc:
            logger.error("Cannot determine Azure subscription: %s", exc)
            return []

    if rt in ("all", "storage"):
        try:
            storage_mod = _require("azure.mgmt.storage", "azure-mgmt-storage")
            storage_client = storage_mod.StorageManagementClient(credential, sub_id)
            actions.extend(rule_azure_storage_block_public(storage_client, sub_id, name_filter, logger))
        except Exception as exc:
            logger.error("Azure Storage client failed: %s", exc)

    if rt in ("all", "nsg", "network", "firewall"):
        try:
            net_mod = _require("azure.mgmt.network", "azure-mgmt-network")
            net_client = net_mod.NetworkManagementClient(credential, sub_id)
            actions.extend(rule_azure_nsg_restrict_inbound(net_client, name_filter, logger))
        except Exception as exc:
            logger.error("Azure Network client failed: %s", exc)

    return actions


def gather_gcp_actions(
    vault_id: Optional[str],
    resource_type: str,
    name_filter: Optional[str],
    logger: logging.Logger,
) -> list[RemediationAction]:
    """Gather all applicable GCP remediation actions.

    Args:
        vault_id: Unused (interface consistency).
        resource_type: Resource type filter.
        name_filter: Glob filter.
        logger: Logger instance.

    Returns:
        List of RemediationAction objects.
    """
    project = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCLOUD_PROJECT")
    if not project:
        print(
            "[ERROR] GCP project not set. Export GOOGLE_CLOUD_PROJECT.",
            file=sys.stderr,
        )
        return []

    actions: list[RemediationAction] = []
    rt = resource_type.lower()

    if rt in ("all", "gcs", "storage", "bucket"):
        try:
            from google.cloud import storage as gcs
            client = gcs.Client(project=project)
            actions.extend(rule_gcp_bucket_remove_public_iam(client, project, name_filter, logger))
            actions.extend(rule_gcp_bucket_enforce_uniform_access(client, project, name_filter, logger))
        except ImportError:
            print("[ERROR] google-cloud-storage not installed. pip install google-cloud-storage", file=sys.stderr)

    if rt in ("all", "firewall", "fw"):
        try:
            from google.cloud import compute_v1
            fw_client = compute_v1.FirewallsClient()
            actions.extend(rule_gcp_firewall_restrict_ingress(fw_client, project, name_filter, logger))
        except ImportError:
            print("[ERROR] google-cloud-compute not installed. pip install google-cloud-compute", file=sys.stderr)

    return actions


# === Dry-Run Engine ===

def run_dry_run(actions: list[RemediationAction], logger: logging.Logger) -> list[RemediationAction]:
    """Simulate all actions without applying any changes.

    Args:
        actions: List of proposed remediation actions.
        logger: Logger instance.

    Returns:
        Updated list with status = DRY_RUN.
    """
    for action in actions:
        action.status = RemediationStatus.DRY_RUN
        logger.info(
            "[DRY-RUN] Would apply: %s | Resource: %s | Risk: %s",
            action.rule_id,
            action.resource_id,
            action.risk_level.value,
        )
    return actions


# === Apply Engine ===

def run_apply(
    actions: list[RemediationAction],
    logger: logging.Logger,
) -> list[RemediationAction]:
    """Apply all remediation actions with per-action error handling.

    Args:
        actions: List of remediation actions to apply.
        logger: Logger instance.

    Returns:
        Updated list with final statuses.
    """
    for action in actions:
        if action.apply_fn is None:
            action.status = RemediationStatus.SKIPPED
            action.error_message = "No apply function defined."
            logger.warning("Skipping %s — no apply function.", action.rule_id)
            continue

        try:
            logger.info(
                "[APPLY] Applying %s on %s (Risk: %s)",
                action.rule_id,
                action.resource_id,
                action.risk_level.value,
            )
            success = action.apply_fn()
            if success:
                action.status = RemediationStatus.APPLIED
                action.applied_at = datetime.datetime.utcnow().isoformat()
                logger.info("[APPLY] SUCCESS: %s on %s", action.rule_id, action.resource_id)
            else:
                action.status = RemediationStatus.FAILED
                action.error_message = "apply_fn returned False."
        except Exception as exc:
            action.status = RemediationStatus.FAILED
            action.error_message = str(exc)
            logger.error(
                "[APPLY] FAILED: %s on %s — %s",
                action.rule_id,
                action.resource_id,
                exc,
            )

        time.sleep(RATE_LIMIT_SLEEP)

    return actions


# === Rollback Hints ===

def print_rollback_hints(actions: list[RemediationAction]) -> None:
    """Print rollback hints for all applied actions.

    Args:
        actions: List of actions that were applied.
    """
    applied = [a for a in actions if a.status == RemediationStatus.APPLIED]
    if not applied:
        return

    print("\n" + "=" * 70)
    print("  📋 ROLLBACK HINTS — Commands to undo applied changes")
    print("=" * 70)
    for action in applied:
        print(f"\n  [{action.rule_id}] {action.title}")
        print(f"  Resource: {action.resource_id}")
        print("  Undo with:")
        for line in action.rollback_hint.splitlines():
            print(f"    {line}")
    print()


def compute_posture_score(actions: list[RemediationAction]) -> tuple[float, float]:
    """Compute a simple posture score before and after remediation.

    Score = percentage of actions that are applied (higher = better posture).
    In dry-run mode, after_score reflects what the posture would be.

    Args:
        actions: List of all actions.

    Returns:
        Tuple of (before_score, after_score) as percentages 0-100.
    """
    if not actions:
        return 100.0, 100.0

    total = len(actions)
    applied = sum(1 for a in actions if a.status in (RemediationStatus.APPLIED, RemediationStatus.DRY_RUN))
    before = 0.0
    after = round((applied / total) * 100, 1)
    return before, after


# === Core Orchestrator ===

def run_orchestration(
    provider: str,
    resource_type: str,
    name_filter: Optional[str],
    dry_run: bool,
    logger: logging.Logger,
) -> RemediationReport:
    """Orchestrate remediation discovery and execution across providers.

    Args:
        provider: Cloud provider (aws/azure/gcp/all).
        resource_type: Resource type filter.
        name_filter: Glob name filter.
        dry_run: If True, simulate only. If False, apply changes.
        logger: Logger instance.

    Returns:
        Completed RemediationReport.
    """
    start_time = datetime.datetime.utcnow().isoformat()
    mode = "dry-run" if dry_run else "apply"

    providers_to_run = (
        ["aws", "azure", "gcp"] if provider == "all" else [provider]
    )

    all_actions: list[RemediationAction] = []

    gatherers = {
        "aws": gather_aws_actions,
        "azure": gather_azure_actions,
        "gcp": gather_gcp_actions,
    }

    for prov in providers_to_run:
        logger.info("Gathering remediation actions for provider: %s", prov)
        gatherer = gatherers.get(prov)
        if gatherer:
            actions = gatherer(None, resource_type, name_filter, logger)
            all_actions.extend(actions)

    if dry_run:
        all_actions = run_dry_run(all_actions, logger)
    else:
        all_actions = run_apply(all_actions, logger)

    status_counts = {s.value: 0 for s in RemediationStatus}
    for a in all_actions:
        status_counts[a.status.value] += 1

    before_score, after_score = compute_posture_score(all_actions)

    return RemediationReport(
        provider=provider,
        mode=mode,
        start_time=start_time,
        end_time=datetime.datetime.utcnow().isoformat(),
        total_actions=len(all_actions),
        applied=status_counts.get(RemediationStatus.APPLIED.value, 0),
        failed=status_counts.get(RemediationStatus.FAILED.value, 0),
        skipped=status_counts.get(RemediationStatus.SKIPPED.value, 0),
        dry_run=status_counts.get(RemediationStatus.DRY_RUN.value, 0),
        actions=all_actions,
        posture_score_before=before_score,
        posture_score_after=after_score,
    )


# === Reporting ===

def report_console(report: RemediationReport) -> None:
    """Render a rich terminal dashboard for the remediation report.

    Args:
        report: The completed remediation report.
    """
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
        from rich.text import Text
        _rich_console(report, Console(), Table, Panel, box, Text)
    except ImportError:
        _plain_console(report)


def _rich_console(
    report: RemediationReport,
    console: Any,
    Table: Any,
    Panel: Any,
    box: Any,
    Text: Any,
) -> None:
    """Internal rich-based console renderer."""
    mode_label = "🔵 DRY-RUN" if report.mode == "dry-run" else "🔴 APPLIED"
    console.print(f"\n[bold blue]⚙  {TOOL_NAME}[/bold blue]  [dim]v{TOOL_VERSION} by {AUTHOR}[/dim]")
    console.print(f"[bold]Mode:[/bold] {mode_label}  [bold]Provider:[/bold] {report.provider.upper()}\n")

    summary = (
        f"[bold]Total Actions:[/bold] {report.total_actions}  "
        f"[green]Applied: {report.applied}[/green]  "
        f"[red]Failed: {report.failed}[/red]  "
        f"[yellow]Dry-Run: {report.dry_run}[/yellow]  "
        f"[dim]Skipped: {report.skipped}[/dim]  "
        f"[bold]Posture Score:[/bold] {report.posture_score_before:.0f}% → [green]{report.posture_score_after:.0f}%[/green]"
    )
    console.print(Panel(summary, title="[yellow]Remediation Summary[/yellow]", expand=False))

    risk_styles = {"SAFE": "green", "MEDIUM": "yellow", "HIGH": "bold red"}
    status_styles = {
        "DRY_RUN": "cyan", "APPLIED": "bold green",
        "FAILED": "bold red", "SKIPPED": "dim", "PENDING": "white",
    }

    table = Table(
        title="Remediation Actions",
        box=box.ROUNDED,
        show_header=True,
        row_styles=["", "on grey15"],
    )
    table.add_column("Status", width=10)
    table.add_column("Risk", width=8)
    table.add_column("Rule ID", width=12)
    table.add_column("Provider", width=8)
    table.add_column("Type", width=14)
    table.add_column("Resource", width=30)
    table.add_column("Action")

    for action in report.actions:
        risk_style = risk_styles.get(action.risk_level.value, "white")
        status_style = status_styles.get(action.status.value, "white")
        table.add_row(
            Text(action.status.value, style=status_style),
            Text(f"{risk_icon(action.risk_level)} {action.risk_level.value}", style=risk_style),
            action.rule_id,
            action.provider.upper(),
            action.resource_type,
            truncate(action.resource_id.split("/")[-1], 28),
            action.title,
        )

    console.print(table)

    if report.mode == "dry-run":
        console.print(
            "\n[dim]📌 This was a DRY-RUN. No changes were made. "
            "To apply, use --apply --confirm --i-understand-risk[/dim]\n"
        )
    else:
        console.print(
            f"\n[green]✅ Remediation complete.[/green] "
            f"Applied: {report.applied} | Failed: {report.failed}\n"
        )

    if report.failed > 0:
        console.print("[red]⚠ Some actions failed. Check --output json for details.[/red]\n")


def _plain_console(report: RemediationReport) -> None:
    """Fallback plain-text console output."""
    print(f"\n{'=' * 60}")
    print(f"  {TOOL_NAME} v{TOOL_VERSION} — {AUTHOR}")
    print(f"  Mode: {report.mode.upper()} | Provider: {report.provider.upper()}")
    print(f"{'=' * 60}")
    print(f"  Total: {report.total_actions}  Applied: {report.applied}  "
          f"Failed: {report.failed}  Dry-Run: {report.dry_run}")
    print(f"  Posture: {report.posture_score_before:.0f}% → {report.posture_score_after:.0f}%")
    print(f"{'=' * 60}")

    for a in report.actions:
        icon = risk_icon(a.risk_level)
        print(f"\n  [{a.status.value}] {icon} {a.rule_id} — {a.title}")
        print(f"    Resource : {truncate(a.resource_id, 70)}")
        print(f"    Before   : {a.before_state}")
        print(f"    After    : {a.after_state}")
        if a.error_message:
            print(f"    Error    : {a.error_message}")


def report_json(report: RemediationReport, output_path: Optional[str]) -> None:
    """Export remediation report as structured JSON.

    Args:
        report: Completed report.
        output_path: File path to write, or None for stdout.
    """
    def _serialize(obj: Any) -> str:
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        if callable(obj):
            return "<function>"
        return str(obj)

    data = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "author": AUTHOR,
        "report": {
            "provider": report.provider,
            "mode": report.mode,
            "start_time": report.start_time,
            "end_time": report.end_time,
            "summary": {
                "total_actions": report.total_actions,
                "applied": report.applied,
                "failed": report.failed,
                "skipped": report.skipped,
                "dry_run": report.dry_run,
                "posture_score_before": report.posture_score_before,
                "posture_score_after": report.posture_score_after,
            },
            "actions": [
                {k: v for k, v in asdict(a).items() if k != "apply_fn"}
                for a in report.actions
            ],
        },
    }

    content = json.dumps(data, indent=2, default=_serialize)

    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
        print(f"[+] JSON report saved to: {output_path}")
    else:
        print(content)


def report_txt(report: RemediationReport, output_path: Optional[str]) -> None:
    """Export a plain-text change log.

    Args:
        report: Completed report.
        output_path: File path, or None for stdout.
    """
    buf = StringIO()
    buf.write(f"{TOOL_NAME} v{TOOL_VERSION} — Change Log\n")
    buf.write(f"Author: {AUTHOR}\n")
    buf.write(f"{'=' * 70}\n")
    buf.write(f"Provider : {report.provider.upper()}\n")
    buf.write(f"Mode     : {report.mode}\n")
    buf.write(f"Started  : {report.start_time}\n")
    buf.write(f"Ended    : {report.end_time}\n")
    buf.write(f"Total    : {report.total_actions}  Applied: {report.applied}  "
              f"Failed: {report.failed}  Dry-Run: {report.dry_run}\n")
    buf.write(f"Posture  : {report.posture_score_before:.0f}% → {report.posture_score_after:.0f}%\n")
    buf.write(f"{'=' * 70}\n\n")

    for a in report.actions:
        buf.write(f"[{a.status.value}] {a.rule_id} — {a.title}\n")
        buf.write(f"  Resource   : {a.resource_id}\n")
        buf.write(f"  Risk Level : {a.risk_level.value}\n")
        buf.write(f"  Description: {a.description}\n")
        buf.write(f"  Before     : {json.dumps(a.before_state)}\n")
        buf.write(f"  After      : {json.dumps(a.after_state)}\n")
        buf.write(f"  Rollback   : {a.rollback_hint}\n")
        if a.error_message:
            buf.write(f"  ERROR      : {a.error_message}\n")
        if a.applied_at:
            buf.write(f"  Applied At : {a.applied_at}\n")
        buf.write("\n")

    content = buf.getvalue()

    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
        print(f"[+] Text report saved to: {output_path}")
    else:
        print(content)


def report_html(report: RemediationReport, output_path: Optional[str]) -> None:
    """Export an HTML before/after dashboard.

    Args:
        report: Completed report.
        output_path: File path to save.
    """
    risk_colors = {"SAFE": "#28a745", "MEDIUM": "#ffc107", "HIGH": "#dc3545"}
    status_colors = {
        "DRY_RUN": "#17a2b8", "APPLIED": "#28a745",
        "FAILED": "#dc3545", "SKIPPED": "#6c757d", "PENDING": "#adb5bd",
    }

    def badge(val: str, colors: dict) -> str:
        c = colors.get(val, "#6c757d")
        return f'<span style="background:{c};color:white;padding:2px 8px;border-radius:4px;font-weight:bold">{val}</span>'

    rows = ""
    for a in report.actions:
        rows += f"""
        <tr>
          <td>{badge(a.status.value, status_colors)}</td>
          <td>{badge(a.risk_level.value, risk_colors)}</td>
          <td><code>{a.rule_id}</code></td>
          <td>{a.provider.upper()}</td>
          <td>{a.resource_type}</td>
          <td style="font-size:0.85em">{truncate(a.resource_id, 50)}</td>
          <td><strong>{a.title}</strong><br><small>{a.description}</small></td>
          <td style="font-size:0.8em"><code>{json.dumps(a.before_state, indent=1)}</code></td>
          <td style="font-size:0.8em"><code>{json.dumps(a.after_state, indent=1)}</code></td>
          <td style="font-size:0.78em;color:#888"><pre>{a.rollback_hint}</pre></td>
        </tr>"""

    mode_color = "#17a2b8" if report.mode == "dry-run" else "#dc3545"
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{TOOL_NAME} — Remediation Report</title>
  <style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #f8f9fa; margin: 0; padding: 20px; color: #333; }}
    h1 {{ color: #2c3e50; border-bottom: 3px solid #e74c3c; padding-bottom: 10px; }}
    .meta {{ color: #666; font-size: 0.9em; }}
    .stats {{ display: flex; gap: 16px; flex-wrap: wrap; margin: 1.5em 0; }}
    .stat {{ background: white; border-radius: 8px; padding: 16px 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); text-align: center; min-width: 120px; }}
    .stat .v {{ font-size: 2em; font-weight: bold; color: #2c3e50; }}
    .stat .l {{ font-size: 0.85em; color: #888; }}
    .mode-badge {{ background: {mode_color}; color: white; padding: 4px 14px; border-radius: 20px; font-weight: bold; font-size: 0.9em; }}
    table {{ border-collapse: collapse; width: 100%; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
    th {{ background: #2c3e50; color: white; padding: 10px 12px; text-align: left; font-size: 0.88em; }}
    td {{ padding: 8px 12px; border-bottom: 1px solid #eee; font-size: 0.85em; vertical-align: top; }}
    tr:hover td {{ background: #f0f4ff; }}
    pre {{ margin: 0; white-space: pre-wrap; }}
    footer {{ color: #999; text-align: center; font-size: 0.8em; margin-top: 3em; }}
  </style>
</head>
<body>
  <h1>⚙ {TOOL_NAME}</h1>
  <p class="meta">
    <span class="mode-badge">{report.mode.upper()}</span> &nbsp;
    <strong>Provider:</strong> {report.provider.upper()} &nbsp;|&nbsp;
    <strong>Started:</strong> {report.start_time[:19]} UTC &nbsp;|&nbsp;
    <strong>Author:</strong> {AUTHOR}
  </p>

  <div class="stats">
    <div class="stat"><div class="v">{report.total_actions}</div><div class="l">Total Actions</div></div>
    <div class="stat"><div class="v" style="color:#28a745">{report.applied}</div><div class="l">Applied</div></div>
    <div class="stat"><div class="v" style="color:#dc3545">{report.failed}</div><div class="l">Failed</div></div>
    <div class="stat"><div class="v" style="color:#17a2b8">{report.dry_run}</div><div class="l">Dry-Run</div></div>
    <div class="stat"><div class="v">{report.posture_score_before:.0f}% → <span style="color:#28a745">{report.posture_score_after:.0f}%</span></div><div class="l">Posture Score</div></div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Status</th><th>Risk</th><th>Rule ID</th><th>Provider</th><th>Type</th>
        <th>Resource</th><th>Action & Description</th><th>Before</th><th>After</th><th>Rollback</th>
      </tr>
    </thead>
    <tbody>
      {rows or '<tr><td colspan="10" style="text-align:center;padding:20px;color:green">✅ No remediations needed!</td></tr>'}
    </tbody>
  </table>

  <footer>
    Generated by {TOOL_NAME} v{TOOL_VERSION} — Author: {AUTHOR}<br>
    ⚠ For authorized remediation of your own environments only.
  </footer>
</body>
</html>"""

    final_path = output_path or f"autorem_report_{report.provider}_{datetime.date.today()}.html"
    Path(final_path).write_text(html, encoding="utf-8")
    print(f"[+] HTML report saved to: {final_path}")


# === CLI ===

def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="autoremediation",
        description=textwrap.dedent(f"""
            {TOOL_NAME} v{TOOL_VERSION}
            ─────────────────────────────────────────────────────────
            Safety-first automated remediation of cloud security
            misconfigurations across AWS, Azure, and GCP.

            ⚠  DRY-RUN IS THE DEFAULT. Nothing is changed without
               --apply --confirm --i-understand-risk.

            Author: {AUTHOR}
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Use --examples to see real-world usage examples for each provider.",
    )

    parser.add_argument(
        "--provider", "-p",
        choices=["aws", "azure", "gcp", "all"],
        required=True,
        help="Cloud provider to remediate (aws/azure/gcp/all).",
    )
    parser.add_argument(
        "--resource-type",
        metavar="TYPE",
        default="all",
        help="Filter by resource type (e.g. all, s3, iam, storage, nsg, firewall). Default: all.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Simulate remediations only — no changes made. This is the default.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        default=False,
        help=(
            "APPLY changes to cloud resources. "
            "Requires --confirm AND --i-understand-risk AND interactive confirmation."
        ),
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        default=False,
        help="Confirm intent to apply changes. Required with --apply.",
    )
    parser.add_argument(
        "--i-understand-risk",
        action="store_true",
        default=False,
        dest="understand_risk",
        help="Acknowledge that applying changes may affect production resources.",
    )
    parser.add_argument(
        "--output", "-o",
        choices=["console", "json", "html", "txt"],
        default="console",
        help="Output format. Default: console.",
    )
    parser.add_argument(
        "--output-file",
        metavar="PATH",
        help="File path for output. Auto-named if not specified.",
    )
    parser.add_argument(
        "--filter", "-f",
        metavar="PATTERN",
        dest="name_filter",
        help="Glob pattern to filter resources by name (e.g. 'prod-*').",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help="API request timeout in seconds (5-300). Default: 30.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable INFO-level logging to stderr.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable DEBUG-level logging (very verbose).",
    )
    parser.add_argument(
        "--examples",
        action="store_true",
        help="Print real-world usage examples and exit.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} v{TOOL_VERSION} by {AUTHOR}",
    )

    return parser


def validate_args(args: argparse.Namespace) -> None:
    """Validate argument combinations for safety.

    Args:
        args: Parsed argparse namespace.

    Raises:
        SystemExit: On unsafe or invalid argument combinations.
    """
    if args.apply:
        if not args.confirm:
            print(
                "[ERROR] --apply requires --confirm. "
                "Rerun with both flags after reviewing the dry-run output.",
                file=sys.stderr,
            )
            sys.exit(1)
        if not args.understand_risk:
            print(
                "[ERROR] --apply requires --i-understand-risk. "
                "Add this flag to acknowledge you accept responsibility for changes.",
                file=sys.stderr,
            )
            sys.exit(1)

    if args.timeout < 5 or args.timeout > 300:
        print("[ERROR] --timeout must be between 5 and 300 seconds.", file=sys.stderr)
        sys.exit(1)


def prompt_final_apply_confirmation() -> bool:
    """Interactively demand the full responsibility acceptance phrase.

    Returns:
        True if the user typed the correct phrase, False otherwise.
    """
    print("\n" + "!" * 70)
    print("  ⛔ FINAL APPLY CONFIRMATION REQUIRED")
    print("!" * 70)
    print(
        "\n  You are about to MODIFY live cloud resources. This cannot be\n"
        "  automatically undone. Review the dry-run output first.\n"
    )
    print(f'  Type exactly: {APPLY_CONFIRMATION_PHRASE}\n')

    try:
        response = input("  Your input: ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Aborted.")
        return False

    if response != APPLY_CONFIRMATION_PHRASE:
        print(
            f'\n[ERROR] Confirmation phrase incorrect. You typed: "{response}"\n'
            f"  Expected: \"{APPLY_CONFIRMATION_PHRASE}\"\n"
            "  Apply aborted.",
            file=sys.stderr,
        )
        return False

    print("\n  ✅ Confirmation accepted. Proceeding with apply...\n")
    return True


def main() -> None:
    """Entry point: parse arguments, run orchestration, output results."""
    parser = build_parser()
    args = parser.parse_args()

    if args.examples:
        print(EXAMPLES_TEXT)
        sys.exit(0)

    print(LEGAL_WARNING)

    validate_args(args)

    logger = setup_logging(verbose=args.verbose, debug=args.debug)

    # Determine actual execution mode
    apply_mode = args.apply and args.confirm and args.understand_risk
    dry_run = not apply_mode

    if apply_mode:
        confirmed = prompt_final_apply_confirmation()
        if not confirmed:
            sys.exit(1)

    mode_label = "DRY-RUN (simulation)" if dry_run else "⚠️  APPLY (modifying resources)"
    print(f"[*] Mode     : {mode_label}")
    print(f"[*] Provider : {args.provider.upper()}")
    print(f"[*] Type     : {args.resource_type}")
    if args.name_filter:
        print(f"[*] Filter   : {args.name_filter}")
    print()

    report = run_orchestration(
        provider=args.provider,
        resource_type=args.resource_type,
        name_filter=args.name_filter,
        dry_run=dry_run,
        logger=logger,
    )

    output_path = args.output_file

    if args.output == "json":
        if not output_path:
            output_path = f"autorem_report_{args.provider}_{datetime.date.today()}.json"
        report_json(report, output_path)
    elif args.output == "html":
        report_html(report, output_path)
    elif args.output == "txt":
        if not output_path:
            output_path = f"autorem_report_{args.provider}_{datetime.date.today()}.txt"
        report_txt(report, output_path)
    else:
        report_console(report)

    if apply_mode and report.applied > 0:
        print_rollback_hints(report.actions)

    if dry_run and report.total_actions > 0:
        print(
            f"[*] {report.total_actions} action(s) would be applied. "
            "Review above and run with --apply --confirm --i-understand-risk to execute.\n"
        )

    sys.exit(1 if report.failed > 0 else 0)


if __name__ == "__main__":
    main()
