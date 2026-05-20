#!/usr/bin/env python3
"""IAMScout - read-only AWS IAM / S3 misconfiguration auditor.

IAMScout audits an AWS account for IAM and S3 misconfigurations that an
attacker could abuse to escalate privileges or expose data:

  * IAM identity policies (inline AND attached managed) that grant ``*:*``.
  * IAM identity policies that grant known privilege-escalation actions.
  * Stale IAM access keys (older than a configurable age, default 90 days).
  * S3 buckets with public ACL grants (AllUsers / AuthenticatedUsers).
  * S3 buckets with a missing or weak public-access-block configuration.

It produces a severity-ranked markdown report.

STRICTLY READ-ONLY
------------------
This tool only ever issues ``list_*`` / ``get_*`` AWS API calls (plus the
read-only ``sts:GetCallerIdentity``). It never creates, updates, attaches,
puts, or deletes anything. That is a deliberate, load-bearing design choice:
an auditor that mutates the account it is auditing is dangerous and cannot
be trusted to run against a third party's cloud. A read-only IAM policy is
all the access this tool needs (see README.md).

Requires: boto3 (`pip install boto3`) and configured AWS credentials.
"""

import argparse
import datetime
import sys

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    ProfileNotFound,
)

# ---------------------------------------------------------------------------
# Privilege-escalation action set.
#
# Each of these IAM actions, if grantable by a principal, opens a path to
# higher privilege. They are not "admin" on their own -- they are the *gates*
# of well-known privesc chains. See README.md "How it works" for two chains
# walked end to end (iam:CreateAccessKey on another user; iam:PassRole +
# lambda:CreateFunction).
# ---------------------------------------------------------------------------
PRIVESC = {
    "iam:CreateAccessKey",      # mint credentials for another user
    "iam:CreateLoginProfile",   # set a console password for a user with none
    "iam:UpdateLoginProfile",   # reset another user's console password
    "iam:AttachUserPolicy",     # attach AdministratorAccess to yourself
    "iam:AttachRolePolicy",     # attach AdministratorAccess to a role you hold
    "iam:PutUserPolicy",        # write an inline allow-* policy on yourself
    "iam:PutRolePolicy",        # write an inline allow-* policy on a role
    "iam:CreatePolicyVersion",  # publish a new (admin) version of a policy
    "iam:SetDefaultPolicyVersion",  # flip a policy back to an admin version
    "iam:PassRole",             # hand a powerful role to a compute service
    "lambda:CreateFunction",    # run code -- pairs with iam:PassRole
    "lambda:InvokeFunction",    # trigger that code
    "ec2:RunInstances",         # boot an instance with an instance profile
    "sts:AssumeRole",           # assume a role you should not be able to
}

# Severity ordering used to sort the final report (lower = more urgent).
SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _as_list(value):
    """Normalise an IAM policy field to a list.

    IAM policy ``Action`` / ``Resource`` fields may be a single string or a
    list of strings. This collapses both forms (and ``None``) into a list so
    callers can treat them uniformly.
    """
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def inspect_statements(policy_doc, principal, policy_label):
    """Inspect one IAM policy document for wildcard and privesc grants.

    This is the shared core used for BOTH inline and attached managed
    policies, so the two code paths cannot drift apart.

    Args:
        policy_doc:   the decoded JSON policy document (a dict).
        principal:    human label for who/what the policy is on, e.g.
                      "user alice".
        policy_label: human label for the policy itself, e.g.
                      "inline policy 'devperms'".

    Returns:
        A list of (severity, detail) finding tuples.
    """
    findings = []
    statements = _as_list(policy_doc.get("Statement"))

    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        # Only "Allow" statements grant power. "Deny" statements are not a
        # misconfiguration on their own, so they are out of scope here.
        if stmt.get("Effect") != "Allow":
            continue

        actions = set(_as_list(stmt.get("Action")))
        resources = set(_as_list(stmt.get("Resource")))

        # *:*  -- effectively AdministratorAccess. Most severe finding.
        if "*" in actions and "*" in resources:
            findings.append((
                "CRITICAL",
                f"{principal}: {policy_label} allows Action '*' on Resource "
                f"'*' (effectively AdministratorAccess)",
            ))

        # Explicit privilege-escalation actions present in the grant.
        privesc_hits = sorted(actions & PRIVESC)
        if privesc_hits:
            findings.append((
                "HIGH",
                f"{principal}: {policy_label} grants privilege-escalation "
                f"action(s): {', '.join(privesc_hits)}",
            ))

        # Service-wide wildcards such as "iam:*" or "s3:*" -- broad, and
        # "iam:*" in particular is a superset of every PRIVESC action.
        service_wildcards = sorted(
            a for a in actions
            if a.endswith(":*") and a != "*"
        )
        if service_wildcards:
            severity = "HIGH" if "iam:*" in service_wildcards else "MEDIUM"
            findings.append((
                severity,
                f"{principal}: {policy_label} grants service-wide "
                f"wildcard action(s): {', '.join(service_wildcards)}",
            ))

    return findings


# ---------------------------------------------------------------------------
# IAM audit
# ---------------------------------------------------------------------------
def audit_iam_inline_policies(iam, user_name):
    """Check a user's INLINE policies for wildcard / privesc grants."""
    findings = []
    paginator = iam.get_paginator("list_user_policies")
    for page in paginator.paginate(UserName=user_name):
        for policy_name in page.get("PolicyNames", []):
            try:
                resp = iam.get_user_policy(
                    UserName=user_name, PolicyName=policy_name
                )
            except ClientError as exc:
                print(f"[warn] get_user_policy {user_name}/{policy_name}: "
                      f"{exc.response['Error']['Code']}")
                continue
            findings += inspect_statements(
                resp["PolicyDocument"],
                f"user {user_name}",
                f"inline policy '{policy_name}'",
            )
    return findings


def audit_iam_attached_policies(iam, user_name):
    """Check a user's ATTACHED MANAGED policies for wildcard / privesc grants.

    An attached managed policy is versioned. We must:
      1. list_attached_user_policies  -> get each policy's ARN
      2. get_policy                   -> find its DefaultVersionId
      3. get_policy_version           -> fetch the actual JSON document
    then run the same statement inspection used for inline policies.

    AWS-managed policies (ARNs under ``arn:aws:iam::aws:policy/``) are still
    inspected -- ``AdministratorAccess`` is an AWS-managed policy and is a
    legitimate finding when attached to a user who should not have it.
    """
    findings = []
    paginator = iam.get_paginator("list_attached_user_policies")
    for page in paginator.paginate(UserName=user_name):
        for attached in page.get("AttachedPolicies", []):
            arn = attached["PolicyArn"]
            policy_name = attached.get("PolicyName", arn)
            try:
                meta = iam.get_policy(PolicyArn=arn)["Policy"]
                default_version = meta["DefaultVersionId"]
                version = iam.get_policy_version(
                    PolicyArn=arn, VersionId=default_version
                )["PolicyVersion"]
            except ClientError as exc:
                print(f"[warn] managed policy {arn}: "
                      f"{exc.response['Error']['Code']}")
                continue

            findings += inspect_statements(
                version["Document"],
                f"user {user_name}",
                f"attached managed policy '{policy_name}'",
            )
    return findings


def audit_iam_access_keys(iam, user_name, max_key_age_days):
    """Flag access keys older than ``max_key_age_days``.

    Long-lived keys are a standing credential-theft risk: the longer a key
    lives, the longer a leaked copy stays valid and the staler any rotation
    discipline is. We only report ACTIVE keys -- an inactive stale key is not
    an immediate threat.
    """
    findings = []
    now = datetime.datetime.now(datetime.timezone.utc)
    paginator = iam.get_paginator("list_access_keys")
    for page in paginator.paginate(UserName=user_name):
        for key in page.get("AccessKeyMetadata", []):
            if key.get("Status") != "Active":
                continue
            age_days = (now - key["CreateDate"]).days
            if age_days > max_key_age_days:
                key_id = key["AccessKeyId"]
                findings.append((
                    "MEDIUM",
                    f"user {user_name}: active access key {key_id} is "
                    f"{age_days} days old (> {max_key_age_days}-day threshold)",
                ))
    return findings


def audit_iam(iam, max_key_age_days):
    """Run all IAM checks across every user in the account.

    ``list_users`` paginates -- on a real account with more than 100 users a
    non-paginated call would silently miss findings, so we use a paginator.
    """
    findings = []
    user_count = 0
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                user_count += 1
                name = user["UserName"]
                findings += audit_iam_access_keys(iam, name, max_key_age_days)
                findings += audit_iam_inline_policies(iam, name)
                findings += audit_iam_attached_policies(iam, name)
    except (ClientError, BotoCoreError) as exc:
        print(f"[warn] IAM audit could not complete: {exc}")

    print(f"[info] IAM: scanned {user_count} user(s), "
          f"{len(findings)} finding(s)")
    return findings


# ---------------------------------------------------------------------------
# S3 audit
# ---------------------------------------------------------------------------
def audit_s3_bucket_acl(s3, bucket_name):
    """Flag a bucket whose ACL grants access to AllUsers / AuthenticatedUsers.

    AllUsers           = anonymous, the whole internet.
    AuthenticatedUsers = ANY authenticated AWS account, not just this one --
                         a common and dangerous misunderstanding.
    """
    findings = []
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        print(f"[warn] get_bucket_acl {bucket_name}: {code}")
        return findings

    for grant in acl.get("Grants", []):
        grantee_uri = grant.get("Grantee", {}).get("URI", "")
        if "AllUsers" in grantee_uri:
            findings.append((
                "CRITICAL",
                f"S3 bucket {bucket_name}: ACL grants "
                f"'{grant.get('Permission')}' to AllUsers (public/anonymous)",
            ))
        elif "AuthenticatedUsers" in grantee_uri:
            findings.append((
                "HIGH",
                f"S3 bucket {bucket_name}: ACL grants "
                f"'{grant.get('Permission')}' to AuthenticatedUsers "
                f"(any AWS account, not just yours)",
            ))
    return findings


def audit_s3_public_access_block(s3, bucket_name):
    """Check the bucket-level Public Access Block (PAB) configuration.

    The PAB is S3's account-/bucket-level safety net: even if an ACL or
    bucket policy tries to make the bucket public, a fully-enabled PAB
    overrides it. There are two failure modes:

      * No PAB configured at all -> get_public_access_block raises a
        ClientError with code 'NoSuchPublicAccessBlockConfiguration'.
        Reported HIGH: the safety net is simply absent.
      * A PAB exists but one or more of its four flags is False ->
        a partial safety net. Reported MEDIUM, naming the weak flags.

    We catch by error CODE, not a bare ``except`` -- an unrelated failure
    (throttling, AccessDenied) must surface, not be silently swallowed.
    """
    findings = []
    pab_flags = (
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    )
    try:
        resp = s3.get_public_access_block(Bucket=bucket_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "NoSuchPublicAccessBlockConfiguration":
            findings.append((
                "HIGH",
                f"S3 bucket {bucket_name}: no Public Access Block configured "
                f"(no safety net against public ACLs/policies)",
            ))
        else:
            print(f"[warn] get_public_access_block {bucket_name}: {code}")
        return findings

    config = resp.get("PublicAccessBlockConfiguration", {})
    disabled = [flag for flag in pab_flags if config.get(flag) is not True]
    if disabled:
        findings.append((
            "MEDIUM",
            f"S3 bucket {bucket_name}: Public Access Block is incomplete -- "
            f"disabled flag(s): {', '.join(disabled)}",
        ))
    return findings


def audit_s3(s3):
    """Run all S3 checks across every bucket in the account."""
    findings = []
    bucket_count = 0
    try:
        # list_buckets is not paginated by the AWS API (it returns every
        # bucket in one response), so a plain call is correct here.
        buckets = s3.list_buckets().get("Buckets", [])
    except (ClientError, BotoCoreError) as exc:
        print(f"[warn] S3 audit could not list buckets: {exc}")
        return findings

    for bucket in buckets:
        bucket_count += 1
        name = bucket["Name"]
        findings += audit_s3_bucket_acl(s3, name)
        findings += audit_s3_public_access_block(s3, name)

    print(f"[info] S3: scanned {bucket_count} bucket(s), "
          f"{len(findings)} finding(s)")
    return findings


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def get_account_context(session):
    """Return (account_id, caller_arn) via the read-only sts:GetCallerIdentity.

    Recording exactly which account and identity was scanned removes any
    ambiguity from the report -- and the call is itself read-only.
    """
    try:
        identity = session.client("sts").get_caller_identity()
        return identity.get("Account", "unknown"), identity.get("Arn", "unknown")
    except (ClientError, BotoCoreError) as exc:
        print(f"[warn] could not determine caller identity: {exc}")
        return "unknown", "unknown"


def write_report(path, findings, account_id, caller_arn, max_key_age_days):
    """Write the severity-ranked markdown report to ``path``."""
    findings = sorted(
        findings, key=lambda f: SEVERITY_RANK.get(f[0], 99)
    )

    # Count findings per severity for the summary line.
    counts = {}
    for severity, _ in findings:
        counts[severity] = counts.get(severity, 0) + 1
    summary = ", ".join(
        f"{counts[s]} {s}"
        for s in sorted(counts, key=lambda s: SEVERITY_RANK.get(s, 99))
    ) or "none"

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# IAMScout Report\n\n")
        fh.write(f"- **Scan date:** {datetime.date.today()}\n")
        fh.write(f"- **AWS account:** `{account_id}`\n")
        fh.write(f"- **Scanned as:** `{caller_arn}`\n")
        fh.write(f"- **Stale-key threshold:** {max_key_age_days} days\n")
        fh.write(f"- **Total findings:** {len(findings)} ({summary})\n\n")
        fh.write("> Read-only audit. IAMScout issues only `list_*` / `get_*` "
                 "AWS API calls; it never modifies the account.\n\n")

        fh.write("## Findings\n\n")
        if not findings:
            fh.write("No misconfigurations found by the current checks.\n")
        else:
            for severity, detail in findings:
                fh.write(f"- **[{severity}]** {detail}\n")

    print(f"[info] {len(findings)} finding(s) ({summary}) -> {path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        prog="iamscout",
        description="Read-only AWS IAM / S3 misconfiguration auditor. "
                    "Issues only list_* / get_* API calls.",
    )
    parser.add_argument(
        "--profile", default=None,
        help="AWS named profile to use (default: environment / default profile)",
    )
    parser.add_argument(
        "--region", default=None,
        help="AWS region for the session (IAM is global; mainly affects STS)",
    )
    parser.add_argument(
        "--max-key-age", type=int, default=90, metavar="DAYS",
        help="Flag active access keys older than this many days (default: 90)",
    )
    parser.add_argument(
        "--out", default="iamscout_report.md",
        help="Path for the markdown report (default: iamscout_report.md)",
    )
    parser.add_argument(
        "--skip-iam", action="store_true",
        help="Skip the IAM checks (audit S3 only)",
    )
    parser.add_argument(
        "--skip-s3", action="store_true",
        help="Skip the S3 checks (audit IAM only)",
    )
    args = parser.parse_args()

    if args.skip_iam and args.skip_s3:
        parser.error("--skip-iam and --skip-s3 together leave nothing to do.")

    # Build the session. Credential / profile problems are caught here so the
    # user gets a clear message instead of a stack trace.
    try:
        session = boto3.Session(
            profile_name=args.profile, region_name=args.region
        )
    except ProfileNotFound as exc:
        print(f"[error] {exc}")
        sys.exit(1)

    account_id, caller_arn = get_account_context(session)
    print(f"[info] auditing AWS account {account_id} as {caller_arn}")

    findings = []
    try:
        if not args.skip_iam:
            findings += audit_iam(session.client("iam"), args.max_key_age)
        if not args.skip_s3:
            findings += audit_s3(session.client("s3"))
    except NoCredentialsError:
        print("[error] no AWS credentials found. Configure credentials first "
              "(see README.md).")
        sys.exit(1)

    write_report(args.out, findings, account_id, caller_arn, args.max_key_age)


if __name__ == "__main__":
    main()
