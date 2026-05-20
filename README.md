# IAMScout

**A read-only AWS IAM and S3 misconfiguration auditor that flags wildcard policies, privilege-escalation actions, stale access keys, and publicly exposed buckets, then writes a severity-ranked markdown report.**

---

## Overview

IAMScout connects to an AWS account with whatever credentials you give it, walks
every IAM user and every S3 bucket, and reports the misconfigurations that an
attacker would look for first. It is a single Python file with one dependency
(`boto3`) and it is **strictly read-only**: it issues only `list_*` / `get_*`
API calls and never creates, updates, attaches, or deletes anything.

The output is one markdown file, sorted most-urgent-first, that a developer or
cloud admin can act on directly.

## Why it exists — threat model

Cloud breaches rarely start with a zero-day. They start with a *misconfiguration*:
an over-broad IAM policy, a leaked long-lived access key, a bucket left public.
IAMScout targets two of the highest-impact misconfiguration classes.

**1. IAM misconfiguration and privilege escalation.**
IAM is the control plane of an AWS account — it decides who can do what. A policy
that *looks* harmless can be a direct path to account takeover. The danger is not
just `Action: "*"` on `Resource: "*"` (obvious AdministratorAccess); it is the
narrow grants whose damage is non-obvious. `iam:CreateAccessKey` looks like an
ordinary admin task — until you notice nothing in the policy restricts *whose*
access key. An attacker who lands a low-privilege identity with one of these
actions can climb to admin without exploiting a single bug. IAMScout flags those
actions explicitly (see the privesc table below).

**2. Public data exposure via S3.**
S3 buckets are public by accident more often than by design. A bucket ACL that
grants `READ` to `AllUsers` exposes its contents to the entire internet
anonymously; a grant to `AuthenticatedUsers` exposes them to *any* AWS account
on Earth — a distinction teams routinely get wrong. The bucket-level **Public
Access Block** is S3's safety net against this, and a bucket without one has no
backstop if an ACL or policy goes wrong. IAMScout checks both.

**3. Stale credentials.**
An access key that has lived for years is a standing risk: the longer it exists,
the more places a copy of it may have leaked, and the staler any rotation
discipline has become. IAMScout flags active keys past a configurable age.

## Features

| Check | Resource | What it flags | Severity |
|---|---|---|---|
| Wildcard grant | IAM inline + attached policies | `Action: "*"` on `Resource: "*"` (effective AdministratorAccess) | CRITICAL |
| Privilege escalation | IAM inline + attached policies | Any known privesc action (see table below) | HIGH |
| Service wildcard | IAM inline + attached policies | `iam:*`, `s3:*`, etc. (`iam:*` is HIGH, others MEDIUM) | HIGH / MEDIUM |
| Stale access key | IAM users | Active access key older than the threshold (default 90 days) | MEDIUM |
| Public bucket ACL | S3 buckets | ACL grant to `AllUsers` (CRITICAL) or `AuthenticatedUsers` (HIGH) | CRITICAL / HIGH |
| Missing Public Access Block | S3 buckets | No PAB configured, or PAB with one or more flags disabled | HIGH / MEDIUM |

Both **inline** and **attached managed** IAM policies are inspected. Attached
managed policies are versioned, so IAMScout resolves each policy's
`DefaultVersionId` and reads that version's document before inspecting it — the
same wildcard/privesc logic then runs on both policy types.

## Installation

Requires **Python 3.8+**.

```bash
git clone https://github.com/VISHNU0906/iamscout.git
cd iamscout
pip install -r requirements.txt
```

### Configuring AWS credentials

IAMScout uses the standard `boto3` credential chain, so any of these work:

- **Environment variables:** `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
  optionally `AWS_SESSION_TOKEN`.
- **Shared credentials file:** `~/.aws/credentials` (Windows:
  `%USERPROFILE%\.aws\credentials`), selected with `--profile`.
- **AWS CLI:** run `aws configure` once and IAMScout picks it up.

**A read-only IAM policy is all this tool needs.** Because IAMScout never
mutates anything, you should run it with a least-privilege identity. AWS's
managed `ReadOnlyAccess` (or the narrower `SecurityAudit`) policy is sufficient;
the specific permissions used are:

```
iam:ListUsers              iam:GetUserPolicy           s3:ListAllMyBuckets
iam:ListUserPolicies       iam:GetPolicy               s3:GetBucketAcl
iam:ListAttachedUserPolicies  iam:GetPolicyVersion     s3:GetBucketPublicAccessBlock
iam:ListAccessKeys         sts:GetCallerIdentity
```

Granting *only* these — and nothing that can write — means the tool physically
cannot harm the account it audits, even if it had a bug.

## Usage

```bash
# Audit the default profile, 90-day stale-key threshold
python iamscout.py

# Audit a named profile, stricter key age, custom report path
python iamscout.py --profile cloud-captain --max-key-age 60 --out audit.md

# Audit only S3 (skip IAM), or only IAM (skip S3)
python iamscout.py --skip-iam
python iamscout.py --skip-s3
```

| Flag | Default | Purpose |
|---|---|---|
| `--profile` | environment / default | AWS named profile to use |
| `--region` | profile default | Session region (IAM is global; mainly affects STS) |
| `--max-key-age DAYS` | `90` | Flag active access keys older than this |
| `--out PATH` | `iamscout_report.md` | Markdown report path |
| `--skip-iam` / `--skip-s3` | off | Audit only one service |

### Sample report excerpt

> **Illustrative example — not from a real scan.** Account ID and ARNs below are
> placeholders. Real output depends entirely on the account you scan.

```markdown
# IAMScout Report

- **Scan date:** 2026-05-21
- **AWS account:** `111122223333`
- **Scanned as:** `arn:aws:iam::111122223333:user/security-audit`
- **Stale-key threshold:** 90 days
- **Total findings:** 5 (1 CRITICAL, 2 HIGH, 2 MEDIUM)

> Read-only audit. IAMScout issues only `list_*` / `get_*` AWS API calls;
> it never modifies the account.

## Findings

- **[CRITICAL]** user deploy-bot: inline policy 'deploy-perms' allows Action '*'
  on Resource '*' (effectively AdministratorAccess)
- **[HIGH]** user ci-runner: attached managed policy 'ci-extra' grants
  privilege-escalation action(s): iam:CreateAccessKey, iam:PassRole
- **[HIGH]** S3 bucket acme-public-assets: ACL grants 'READ' to AuthenticatedUsers
  (any AWS account, not just yours)
- **[MEDIUM]** user legacy-svc: active access key AKIA...EXAMPLE is 412 days old
  (> 90-day threshold)
- **[MEDIUM]** S3 bucket acme-logs: Public Access Block is incomplete --
  disabled flag(s): RestrictPublicBuckets
```

## How it works — the depth spine

The interesting question is not "how do I list IAM policies" — it is **why a
single, narrow IAM action can be a path to full account takeover**, and **why an
audit tool must be read-only**.

### Privilege-escalation chain 1 — `iam:CreateAccessKey` on another user

Suppose an attacker compromises a low-privilege identity — say a CI service user
whose policy includes:

```json
{ "Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "*" }
```

This looks like a routine permission. But `Resource: "*"` means it applies to
**every user in the account**, not just the CI user itself. The attacker runs:

```
aws iam create-access-key --user-name admin
```

AWS hands back a brand-new access key ID and secret **for the `admin` user**.
The attacker exports those credentials and is now operating as `admin` — full
privileges. No password was cracked, no login occurred, and in CloudTrail this
shows up as an ordinary `CreateAccessKey` call, not as anything that screams
"privilege escalation." The fix is to scope the `Resource` to the calling
identity's own ARN (or to deny `iam:CreateAccessKey` entirely for service
users). IAMScout flags `iam:CreateAccessKey` precisely because its blast radius
depends on a `Resource` scope that is almost always too wide.

### Privilege-escalation chain 2 — `iam:PassRole` + `lambda:CreateFunction`

This chain needs two actions and one pre-existing powerful role. Suppose the
attacker's identity can do:

```json
{ "Effect": "Allow",
  "Action": ["lambda:CreateFunction", "lambda:InvokeFunction", "iam:PassRole"],
  "Resource": "*" }
```

and the account already has a role — call it `LambdaAdminRole` — whose trust
policy allows `lambda.amazonaws.com` to assume it and whose permissions are
effectively admin. The attacker:

1. Writes a tiny Lambda function whose code does whatever they want as admin
   (e.g. `iam:AttachUserPolicy` to give themselves `AdministratorAccess`).
2. Calls `lambda:CreateFunction`, **passing `LambdaAdminRole` as the execution
   role** — this is the step `iam:PassRole` gates.
3. Calls `lambda:InvokeFunction`. The function runs *with the admin role's
   permissions* and executes the attacker's code.

`iam:PassRole` is the linchpin: without it, AWS refuses to let you hand a role to
a service. It is also the most misunderstood IAM action — teams grant it broadly
("the deploy pipeline needs to pass roles") without realising that
`iam:PassRole` on `Resource: "*"` plus *any* "run code" action (`lambda:CreateFunction`,
`ec2:RunInstances`, `glue:CreateDevEndpoint`, ...) is a generic privilege-escalation
primitive. IAMScout flags `iam:PassRole`, `lambda:CreateFunction`,
`lambda:InvokeFunction`, and `ec2:RunInstances` so this combination surfaces in
the report.

### Why the tool is strictly read-only

IAMScout issues **only** `list_*` and `get_*` API calls (plus the read-only
`sts:GetCallerIdentity` to record which account was scanned). This is verifiable:
search the source for `create_`, `put_`, `delete_`, `update_`, `attach_`, or
`detach_` and you will find none against an AWS client.

That constraint is deliberate and load-bearing:

- **An auditor that mutates the account it audits cannot be trusted.** If you run
  a tool against a client's, an employer's, or a bug-bounty target's cloud, the
  ironclad guarantee "this only reads" is what makes running it acceptable. A
  tool that *might* write is a liability no matter how careful its code is.
- **It enables least-privilege operation.** Because the tool only reads, it can
  be run with a credentials set that is granted *only* read permissions (see
  Installation). A bug in a read-only tool running under a read-only role
  cannot escalate into damage — the AWS authorization layer is a second,
  independent guarantee on top of the code.
- **It keeps the audit honest.** A read-only audit observes the account exactly
  as it is. A tool that creates a "test policy" to probe behaviour has changed
  the very thing it is measuring.

### Privilege-escalation actions checked

| Action | Why it enables escalation |
|---|---|
| `iam:CreateAccessKey` | Mint long-lived credentials for any user (chain 1 above) |
| `iam:CreateLoginProfile` | Set a console password for a user that has none, then log in as them |
| `iam:UpdateLoginProfile` | Reset another user's console password and take over their session |
| `iam:AttachUserPolicy` | Attach `AdministratorAccess` directly to your own user |
| `iam:AttachRolePolicy` | Attach `AdministratorAccess` to a role you can assume |
| `iam:PutUserPolicy` | Write an inline `Allow *:*` policy onto yourself |
| `iam:PutRolePolicy` | Write an inline `Allow *:*` policy onto a role you hold |
| `iam:CreatePolicyVersion` | Publish a new, admin-level version of an existing managed policy |
| `iam:SetDefaultPolicyVersion` | Switch a managed policy back to an older admin version |
| `iam:PassRole` | Hand a powerful role to a compute service (linchpin of chain 2) |
| `lambda:CreateFunction` | Run arbitrary code; pairs with `iam:PassRole` |
| `lambda:InvokeFunction` | Trigger that code |
| `ec2:RunInstances` | Boot an instance attached to a powerful instance profile |
| `sts:AssumeRole` | Assume a role whose trust policy is too permissive |

## Limitations

IAMScout is intentionally small and honest about what it does *not* do:

- **Users only.** It audits IAM **users**; it does not yet inspect roles or
  groups, so privesc actions reachable only through a group membership or an
  assumed role are missed.
- **No policy simulation.** It performs static, structural inspection of policy
  documents. It does not run `iam:SimulatePrincipalPolicy`, so it cannot resolve
  the *effective* permissions produced by the interaction of inline policies,
  attached policies, group policies, permission boundaries, and SCPs.
- **No `Condition` analysis.** A statement with a restrictive `Condition` block
  may be safer than IAMScout reports; conditions are not currently evaluated.
- **No bucket-policy check.** S3 buckets can also be made public via a *bucket
  policy* (not just an ACL). IAMScout checks ACLs and the Public Access Block
  but not the bucket policy document itself.
- **No `NotAction` / `NotResource`.** Inverse-grant statements are not analysed.
- **Snapshot in time.** The report reflects the account at the moment of the
  scan only.

## Roadmap

- Audit IAM **roles** and **groups**, not just users.
- Inspect S3 **bucket policies** for public `Principal: "*"` statements.
- Evaluate IAM `Condition` blocks to cut false positives.
- Optionally use `iam:SimulatePrincipalPolicy` for effective-permission analysis.
- Emit JSON and SARIF alongside markdown so the report can feed CI / dashboards.
- Add EC2 security-group and unencrypted-volume checks.

## Authorized use

This tool is for auditing AWS accounts **you own or are explicitly authorized to
assess**. It is read-only by design, but scanning an account is still an action
you must have permission to take. Do not point IAMScout at accounts you do not
own or have written authorization for.
