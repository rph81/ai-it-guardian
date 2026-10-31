# AWS posture agent

Reviews Amazon Web Services accounts the way AWS Security Hub, Prowler, Wiz and Prisma Cloud do, against the CIS AWS
Foundations Benchmark (shown as "CIS AWS Foundations" in the compliance view when the agent ran). Read-only.

## Access (recommended: a role with an external ID)

1. In the **customer's** account: IAM › Roles › Create role › *AWS account* › *Another AWS account*: your Guardian
   account ID, **Require external ID** (a random value). Attach **SecurityAudit** and **ViewOnlyAccess**, nothing
   else. Name it `GuardianReadOnly`.
2. In **your** account: an IAM user `guardian-assume` whose only permission is `sts:AssumeRole` on
   `arn:aws:iam::*:role/GuardianReadOnly`. Create an access key.
3. Settings › Connectors › Amazon Web Services: the access key and secret, the role ARN and the external ID.
   Optionally the regions to check (default: every enabled region, up to 20).

Without a role ARN the keys are used directly; they must then carry only the two read-only policies. The test shows
the account, the identity and the regions, and warns when keys of a user in the customer account are used directly.

Guardian signs every request itself (AWS Signature Version 4; checked against AWS's published example), so no SDK is
installed. The temporary role credentials last one hour and live only in the run's memory.

## Reads

| Read | Scope | Looks for |
|---|---|---|
| identity, iam_summary | Account | Root without MFA, root access keys, password policy |
| credential_report | Account | Console users without MFA, keys older than 90 days or unused, unused users, root use |
| admin_policies | Account | Customer-managed policies allowing `*` on `*` |
| s3_buckets | Account | Account / bucket Block Public Access, public bucket policies, encryption, versioning, logging |
| cloudtrail | Account | Multi-region trail logging, log file validation, KMS |
| security_groups_open | Per region | SSH, RDP, SMB, databases or all ports open to 0.0.0.0/0 or ::/0 |
| instances | Per region | Public IPs, IMDSv1 allowed, security groups |
| public_snapshots_images | Per region | EBS snapshots or AMIs anyone can use |
| ebs_encryption_default, rds_instances | Per region | Encryption by default; public, unencrypted or unbacked-up databases |
| guardduty, security_hub, config_recorder | Per region | Detection services off; open high / critical findings |
| kms_rotation | Per region | Customer keys without rotation |

Findings use assets like `aws/<account>/<resource>` and get priorities, ATT&CK techniques and tickets like any other.
Code: `guardian/awsposture.py`.
