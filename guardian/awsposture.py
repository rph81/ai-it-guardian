"""AWS posture: fixed, read-only API calls signed with AWS Signature Version 4 (no SDK needed).

Credentials: an access key of a Guardian IAM user that may only call sts:AssumeRole, plus the customer's read-only role
(SecurityAudit + ViewOnlyAccess) and its external ID; or, simpler, an access key that itself has only those read-only
policies. The agent picks a query name; this code signs and sends the request. Nothing here can change anything:
every call is a Describe/Get/List (or the read-only credential report and Security Hub finding search).
"""
import csv
import datetime as dt
import hashlib
import hmac
import io
import json
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

REGION_RX = re.compile(r"^[a-z]{2}(-gov)?-[a-z]+-\d$")
ARN_RX = re.compile(r"^arn:aws(-us-gov|-cn)?:iam::\d{12}:role/[\w+=,.@/-]{1,128}$")
MAX_REGIONS = 20


class AwsError(Exception):
    pass


def _sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def request(creds, service, region, method="GET", host=None, path="/", params=None, body=b"", headers=None, timeout=30):
    """One SigV4-signed request. Returns (status, body bytes)."""
    host = host or f"{service}.{region}.amazonaws.com"
    now = dt.datetime.now(dt.timezone.utc)
    amz, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    q = "&".join(f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(str(v), safe='-_.~')}" for k, v in sorted((params or {}).items()))
    h = {"host": host, "x-amz-date": amz, "x-amz-content-sha256": hashlib.sha256(body).hexdigest(), **{k.lower(): v for k, v in (headers or {}).items()}}
    if creds.get("session_token"):
        h["x-amz-security-token"] = creds["session_token"]
    signed = ";".join(sorted(h))
    canon = "\n".join([method, urllib.parse.quote(path, safe="/-_.~"), q, "".join(f"{k}:{h[k].strip()}\n" for k in sorted(h)), signed,
                       h["x-amz-content-sha256"]])
    scope = f"{day}/{region}/{service}/aws4_request"
    sts = "\n".join(["AWS4-HMAC-SHA256", amz, scope, hashlib.sha256(canon.encode()).hexdigest()])
    k = _sign(_sign(_sign(_sign(("AWS4" + creds["secret_key"]).encode(), day), region), service), "aws4_request")
    h["authorization"] = (f"AWS4-HMAC-SHA256 Credential={creds['access_key']}/{scope}, SignedHeaders={signed}, "
                          f"Signature={hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()}")
    req = urllib.request.Request(f"https://{host}{path}" + (f"?{q}" if q else ""), data=body or None, method=method,
                                 headers={**{k: v for k, v in h.items() if k != "host"}, "User-Agent": "AI-IT-Guardian"})
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=timeout) as r:
            return r.status, r.read(16 * 2**20)
    except urllib.error.HTTPError as e:
        return e.code, e.read(20000)
    except (urllib.error.URLError, OSError) as e:
        raise AwsError(f"AWS unreachable: {getattr(e, 'reason', e)}")


def _xml(data):
    if b"<!DOCTYPE" in data[:2000] or b"<!ENTITY" in data[:20000]:
        raise AwsError("unexpected XML")
    root = ET.fromstring(data)
    for e in root.iter():                              # drop namespaces
        e.tag = e.tag.split("}")[-1]
    return root


def _err(status, data):
    try:
        r = _xml(data)
        code, msg = r.findtext(".//Code") or "", r.findtext(".//Message") or ""
    except Exception:                                  # noqa: BLE001 - JSON or empty error bodies
        try:
            j = json.loads(data or b"{}")
            code, msg = j.get("__type", "") or j.get("code", ""), j.get("message") or j.get("Message") or ""
        except ValueError:
            code, msg = "", data[:200].decode(errors="replace")
    hint = " (the role lacks SecurityAudit / ViewOnlyAccess here)" if status in (401, 403) or "AccessDenied" in code else ""
    return AwsError(f"{code or status}: {msg[:250]}{hint}")


def query_api(creds, service, region, action, version, params=None, host=None):
    """AWS Query protocol (IAM, EC2, STS, RDS): GET with Action/Version; returns the parsed XML root."""
    st, data = request(creds, service, region, "GET", host, "/", {"Action": action, "Version": version, **(params or {})})
    if st != 200:
        raise _err(st, data)
    return _xml(data)


def json_api(creds, service, region, target, payload=None):
    """AWS JSON 1.1 protocol (CloudTrail, Config, KMS)."""
    st, data = request(creds, service, region, "POST", body=json.dumps(payload or {}).encode(),
                       headers={"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": target})
    if st != 200:
        raise _err(st, data)
    return json.loads(data or b"{}")


def rest_api(creds, service, region, method, path, payload=None, host=None):
    """REST JSON (GuardDuty, Security Hub)."""
    body = json.dumps(payload).encode() if payload is not None else b""
    st, data = request(creds, service, region, method, host, path, body=body, headers={"Content-Type": "application/json"} if body else None)
    if st != 200:
        raise _err(st, data)
    return json.loads(data or b"{}")


def credentials(f):
    """Base keys, or temporary keys of the customer's role when a role ARN is given (sts:AssumeRole with external ID)."""
    base = {"access_key": (f.get("access_key_id") or "").strip(), "secret_key": f.get("secret_access_key") or ""}
    if not re.fullmatch(r"(AKIA|ASIA)[A-Z0-9]{16}", base["access_key"]) or len(base["secret_key"]) < 30:
        raise AwsError("Access key ID looks like AKIA… (20 characters) and the secret is 40 characters")
    role = (f.get("role_arn") or "").strip()
    if not role:
        return base
    if not ARN_RX.match(role):
        raise AwsError("The role ARN looks like arn:aws:iam::123456789012:role/GuardianReadOnly")
    params = {"RoleArn": role, "RoleSessionName": "ai-guardian", "DurationSeconds": 3600}
    if f.get("external_id"):
        params["ExternalId"] = f["external_id"].strip()
    r = query_api(base, "sts", "us-east-1", "AssumeRole", "2011-06-15", params, host="sts.amazonaws.com")
    c = r.find(".//Credentials")
    if c is None:
        raise AwsError("AssumeRole returned no credentials")
    return {"access_key": c.findtext("AccessKeyId"), "secret_key": c.findtext("SecretAccessKey"), "session_token": c.findtext("SessionToken")}


def whoami(creds):
    r = query_api(creds, "sts", "us-east-1", "GetCallerIdentity", "2011-06-15", host="sts.amazonaws.com")
    return {"account": r.findtext(".//Account"), "arn": r.findtext(".//Arn")}


def regions(creds, f):
    only = [x for x in (f.get("regions") or "").replace(",", " ").split() if REGION_RX.match(x)]
    if only:
        return only[:MAX_REGIONS]
    r = query_api(creds, "ec2", "us-east-1", "DescribeRegions", "2016-11-15")
    return sorted(i.findtext("regionName") for i in r.iter("item") if i.findtext("regionName"))[:MAX_REGIONS]


def _items(root, tag="item"):
    return [{c.tag: (c.text or "").strip() for c in it if len(c) == 0} for it in root.iter(tag)]


ADMIN_PORTS = {22: "SSH", 3389: "RDP", 445: "SMB", 1433: "SQL Server", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
               6379: "Redis", 9200: "Elasticsearch", 5985: "WinRM", 5986: "WinRM"}


def _open_groups(creds, region):
    r = query_api(creds, "ec2", region, "DescribeSecurityGroups", "2016-11-15")
    out = []
    for sg in r.find("securityGroupInfo") or []:
        name, gid = sg.findtext("groupName"), sg.findtext("groupId")
        for p in sg.findall("ipPermissions/item"):
            world = [x.findtext("cidrIp") for x in p.findall("ipRanges/item")] + [x.findtext("cidrIpv6") for x in p.findall("ipv6Ranges/item")]
            if not any(w in ("0.0.0.0/0", "::/0") for w in world):
                continue
            proto, lo, hi = p.findtext("ipProtocol"), int(p.findtext("fromPort") or 0), int(p.findtext("toPort") or 65535)
            hit = [f"{port} ({n})" for port, n in ADMIN_PORTS.items() if proto in ("-1", "tcp") and lo <= port <= hi]
            if proto == "-1" or hit:
                out.append({"region": region, "group": gid, "name": name, "protocol": proto, "ports": f"{lo}-{hi}",
                            "exposes": hit or ["all ports"], "vpc": sg.findtext("vpcId")})
    return out


def _instances(creds, region):
    r = query_api(creds, "ec2", region, "DescribeInstances", "2016-11-15")
    out = []
    for i in r.iter("instancesSet"):
        for it in i.findall("item"):
            out.append({"region": region, "id": it.findtext("instanceId"), "state": it.findtext("instanceState/name"),
                        "public_ip": it.findtext("ipAddress"), "imds_tokens": it.findtext("metadataOptions/httpTokens"),
                        "image": it.findtext("imageId"), "platform": it.findtext("platformDetails"),
                        "name": next((t.findtext("value") for t in it.findall("tagSet/item") if t.findtext("key") == "Name"), None),
                        "groups": [g.findtext("groupId") for g in it.findall("groupSet/item")]})
    return out


def _public_snapshots(creds, region):
    r = query_api(creds, "ec2", region, "DescribeSnapshots", "2016-11-15", {"Owner.1": "self", "RestorableBy.1": "all"})
    snaps = [{"region": region, "snapshot": s["snapshotId"], "volume_size": s.get("volumeSize"), "encrypted": s.get("encrypted")}
             for s in _items(r) if s.get("snapshotId")]
    r = query_api(creds, "ec2", region, "DescribeImages", "2016-11-15", {"Owner.1": "self", "ExecutableBy.1": "all"})
    imgs = [{"region": region, "image": i["imageId"], "name": i.get("name")} for i in _items(r) if i.get("imageId")]
    return {"snapshots": snaps, "images": imgs}


def _ebs_default(creds, region):
    r = query_api(creds, "ec2", region, "GetEbsEncryptionByDefault", "2016-11-15")
    return {"region": region, "encrypted_by_default": r.findtext(".//ebsEncryptionByDefault") == "true"}


def _rds(creds, region):
    r = query_api(creds, "rds", region, "DescribeDBInstances", "2014-10-31")
    return [{"region": region, "db": d.findtext("DBInstanceIdentifier"), "engine": f"{d.findtext('Engine')} {d.findtext('EngineVersion')}",
             "public": d.findtext("PubliclyAccessible") == "true", "encrypted": d.findtext("StorageEncrypted") == "true",
             "backup_days": d.findtext("BackupRetentionPeriod"), "multi_az": d.findtext("MultiAZ") == "true",
             "deletion_protection": d.findtext("DeletionProtection") == "true"} for d in r.iter("DBInstance")]


def _guardduty(creds, region):
    d = rest_api(creds, "guardduty", region, "GET", "/detector")
    ids = d.get("detectorIds") or []
    out = {"region": region, "enabled": bool(ids)}
    if ids:
        st = rest_api(creds, "guardduty", region, "GET", f"/detector/{ids[0]}")
        out["status"] = st.get("status")
        stats = rest_api(creds, "guardduty", region, "POST", f"/detector/{ids[0]}/findings/statistics",
                         {"findingStatisticTypes": ["COUNT_BY_SEVERITY"], "findingCriteria": {"criterion": {"service.archived": {"eq": ["false"]}}}})
        out["open_findings_by_severity"] = (stats.get("findingStatistics") or {}).get("countBySeverity")
    return out


def _securityhub(creds, region):
    try:
        hub = rest_api(creds, "securityhub", region, "GET", "/accounts")
    except AwsError as e:
        if "InvalidAccessException" in str(e) or "not subscribed" in str(e).lower():
            return {"region": region, "enabled": False}
        raise
    std = rest_api(creds, "securityhub", region, "POST", "/standards/get", {})
    f = rest_api(creds, "securityhub", region, "POST", "/findings", {"MaxResults": 50, "Filters": {
        "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}], "WorkflowStatus": [{"Value": "NEW", "Comparison": "EQUALS"}],
        "SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}, {"Value": "HIGH", "Comparison": "EQUALS"}]}})
    return {"region": region, "enabled": True, "hub": hub.get("HubArn"),
            "standards": [s.get("StandardsArn", "").split("/")[-3:] for s in std.get("StandardsSubscriptions") or []],
            "critical_high_findings": [{"title": x.get("Title"), "severity": (x.get("Severity") or {}).get("Label"),
                                        "resource": ((x.get("Resources") or [{}])[0]).get("Id")} for x in f.get("Findings") or []]}


def _config(creds, region):
    st = json_api(creds, "config", region, "StarlingDoveService.DescribeConfigurationRecorderStatus")
    rec = st.get("ConfigurationRecordersStatus") or []
    return {"region": region, "recording": any(r.get("recording") for r in rec), "recorders": len(rec)}


def _kms(creds, region):
    keys = json_api(creds, "kms", region, "TrentService.ListKeys", {"Limit": 100}).get("Keys") or []
    out = []
    for k in keys[:50]:
        meta = json_api(creds, "kms", region, "TrentService.DescribeKey", {"KeyId": k["KeyId"]}).get("KeyMetadata") or {}
        if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled" or meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
            continue
        rot = json_api(creds, "kms", region, "TrentService.GetKeyRotationStatus", {"KeyId": k["KeyId"]})
        out.append({"region": region, "key": k["KeyId"], "rotation": rot.get("KeyRotationEnabled")})
    return out


def _trails(creds, region):
    tr = json_api(creds, "cloudtrail", region, "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.DescribeTrails",
                  {"includeShadowTrails": True}).get("trailList") or []
    out = []
    for t in tr:
        try:
            s = json_api(creds, "cloudtrail", t.get("HomeRegion") or region, "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.GetTrailStatus",
                         {"Name": t["TrailARN"]})
        except AwsError:
            s = {}
        out.append({"name": t.get("Name"), "multi_region": t.get("IsMultiRegionTrail"), "home": t.get("HomeRegion"),
                    "log_validation": t.get("LogFileValidationEnabled"), "kms": bool(t.get("KmsKeyId")), "bucket": t.get("S3BucketName"),
                    "logging": s.get("IsLogging"), "organization": t.get("IsOrganizationTrail")})
    return out


def _s3(creds, account):
    st, data = request(creds, "s3", "us-east-1", "GET", "s3.amazonaws.com", "/")
    if st != 200:
        raise _err(st, data)
    names = [b.findtext("Name") for b in _xml(data).iter("Bucket")][:200]
    acct = {}
    st, data = request(creds, "s3", "us-east-1", "GET", f"{account}.s3-control.us-east-1.amazonaws.com", "/v20180820/configuration/publicAccessBlock",
                       headers={"x-amz-account-id": account})
    if st == 200:
        acct = {c.tag: c.text == "true" for c in _xml(data).iter() if c.tag.startswith(("Block", "Ignore", "Restrict"))}
    out = []
    for n in names:
        b = {"bucket": n}
        st, data = request(creds, "s3", "us-east-1", "GET", "s3.amazonaws.com", f"/{n}", {"location": ""})
        region = (_xml(data).text or "us-east-1") if st == 200 else "us-east-1"
        host = f"s3.{region}.amazonaws.com"
        b["region"] = region
        for key, params in (("public_access_block", {"publicAccessBlock": ""}), ("policy_status", {"policyStatus": ""}),
                            ("encryption", {"encryption": ""}), ("versioning", {"versioning": ""}), ("logging", {"logging": ""})):
            st, data = request(creds, "s3", region, "GET", host, f"/{n}", params)
            if st == 200:
                r = _xml(data)
                b[key] = {c.tag: c.text for c in r.iter() if len(c) == 0 and c.text} or True
            else:
                b[key] = None if st == 404 else f"error {st}"
        out.append(b)
    return {"account_public_access_block": acct or None, "buckets": out}


def _credential_report(creds):
    for _ in range(10):
        r = query_api(creds, "iam", "us-east-1", "GenerateCredentialReport", "2010-05-08", host="iam.amazonaws.com")
        if r.findtext(".//State") == "COMPLETE":
            break
        time.sleep(2)
    r = query_api(creds, "iam", "us-east-1", "GetCredentialReport", "2010-05-08", host="iam.amazonaws.com")
    import base64
    rows = list(csv.DictReader(io.StringIO(base64.b64decode(r.findtext(".//Content") or "").decode())))
    keep = ("user", "arn", "password_enabled", "password_last_used", "mfa_active", "access_key_1_active", "access_key_1_last_rotated",
            "access_key_1_last_used_date", "access_key_2_active", "access_key_2_last_rotated", "access_key_2_last_used_date", "user_creation_time")
    return [{k: row.get(k) for k in keep} for row in rows]


def _iam_summary(creds):
    r = query_api(creds, "iam", "us-east-1", "GetAccountSummary", "2010-05-08", host="iam.amazonaws.com")
    s = {e.findtext("key"): e.findtext("value") for e in r.iter("entry")}
    try:
        p = query_api(creds, "iam", "us-east-1", "GetAccountPasswordPolicy", "2010-05-08", host="iam.amazonaws.com")
        pol = {c.tag: c.text for c in p.find(".//PasswordPolicy") or []}
    except AwsError:
        pol = None
    return {"root_mfa": s.get("AccountMFAEnabled") == "1", "root_access_keys": s.get("AccountAccessKeysPresent") == "1",
            "users": s.get("Users"), "roles": s.get("Roles"), "policies": s.get("Policies"), "password_policy": pol}


def _admin_policies(creds):
    """Customer-managed policies that allow every action on every resource."""
    r = query_api(creds, "iam", "us-east-1", "ListPolicies", "2010-05-08", {"Scope": "Local", "OnlyAttached": "true", "MaxItems": 200}, host="iam.amazonaws.com")
    out = []
    for p in list(r.iter("member"))[:100]:
        arn, ver = p.findtext("Arn"), p.findtext("DefaultVersionId")
        if not arn or not ver:
            continue
        v = query_api(creds, "iam", "us-east-1", "GetPolicyVersion", "2010-05-08", {"PolicyArn": arn, "VersionId": ver}, host="iam.amazonaws.com")
        doc = json.loads(urllib.parse.unquote(v.findtext(".//Document") or "{}"))
        sts = doc.get("Statement") or []
        sts = sts if isinstance(sts, list) else [sts]
        if any(s.get("Effect") == "Allow" and "*" in (s.get("Action") if isinstance(s.get("Action"), list) else [s.get("Action")])
               and "*" in (s.get("Resource") if isinstance(s.get("Resource"), list) else [s.get("Resource")]) for s in sts):
            out.append({"policy": p.findtext("PolicyName"), "arn": arn, "attachments": p.findtext("AttachmentCount")})
    return out


GLOBAL = {"identity": lambda c, a, f: whoami(c), "iam_summary": lambda c, a, f: _iam_summary(c), "credential_report": lambda c, a, f: _credential_report(c),
          "admin_policies": lambda c, a, f: _admin_policies(c), "s3_buckets": lambda c, a, f: _s3(c, a), "cloudtrail": lambda c, a, f: _trails(c, "us-east-1")}
def _bedrock(creds, region):
    """Bedrock in this region: whether model calls are logged, and the guardrails that exist (both read-only)."""
    try:
        log = rest_api(creds, "bedrock", region, "GET", "/logging/modelinvocations")
        guards = rest_api(creds, "bedrock", region, "GET", "/guardrails")
    except AwsError as e:
        if "not" in str(e).lower() and ("subscribed" in str(e).lower() or "available" in str(e).lower()):
            return {"region": region, "bedrock": "not available"}
        raise
    cfg = log.get("loggingConfig") or {}
    return {"region": region, "invocation_logging": bool(cfg), "log_text": cfg.get("textDataDeliveryEnabled"),
            "log_destinations": [k for k in ("cloudWatchConfig", "s3Config") if cfg.get(k)],
            "guardrails": [g.get("name") for g in guards.get("guardrails") or []][:20]}


REGIONAL = {"security_groups_open": _open_groups, "instances": _instances, "public_snapshots_images": _public_snapshots,
            "ebs_encryption_default": _ebs_default, "rds_instances": _rds, "guardduty": _guardduty, "security_hub": _securityhub,
            "config_recorder": _config, "kms_rotation": _kms, "bedrock": _bedrock}
QUERIES = list(GLOBAL) + list(REGIONAL)


def run(f, query, region=None):
    """One named read. Regional reads cover every enabled region (or the connector's list) unless one region is given."""
    if query not in QUERIES:
        raise AwsError("unknown query")
    creds = credentials(f)
    if query in GLOBAL:
        account = whoami(creds)["account"] if query == "s3_buckets" else None
        return GLOBAL[query](creds, account, f)
    regs = [region] if region and REGION_RX.match(region) else regions(creds, f)
    out, errors = [], []
    for reg in regs:
        try:
            r = REGIONAL[query](creds, reg)
            out.extend(r if isinstance(r, list) else [r])
        except AwsError as e:
            errors.append(f"{reg}: {e}")
    return {"regions": regs, "rows": out, **({"errors": errors[:10]} if errors else {})}


def test(f):
    """Connection test: who we are, which regions we see, and a warning when the identity can change things."""
    creds = credentials(f)
    me = whoami(creds)
    regs = regions(creds, f)
    details = [f"Account {me['account']} as {me['arn'].split(':', 5)[-1]}", f"Regions: {len(regs)} ({', '.join(regs[:6])}{'…' if len(regs) > 6 else ''})"]
    level = "ok"
    try:
        _iam_summary(creds)
        details.append("IAM, S3, EC2, CloudTrail, GuardDuty, Security Hub, Config, KMS and RDS reads available")
    except AwsError as e:
        level = "warn"
        details.append(f"IAM read refused: {e}")
    if ":user/" in me["arn"] and not f.get("role_arn"):
        details.append("Tip: use a role with an external ID instead of a user's keys in the customer account")
    return level, "Connected (read-only)", details
