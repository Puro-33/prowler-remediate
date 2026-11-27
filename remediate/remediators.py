from botocore.exceptions import ClientError

from remediate.models import Plan

BLOCK_ALL = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


class Remediator:
    check_id = ""

    def __init__(self, client):
        self.client = client

    def plan(self, finding) -> Plan:
        raise NotImplementedError

    def snapshot(self, finding) -> dict:
        raise NotImplementedError

    def apply(self, finding, snapshot):
        raise NotImplementedError

    def restore(self, finding, snapshot):
        raise NotImplementedError


class S3PublicAccess(Remediator):
    check_id = "s3_bucket_public_access"

    def _pab(self, finding):
        s3 = self.client("s3", finding.region)
        try:
            return s3.get_public_access_block(Bucket=finding.resource_id)[
                "PublicAccessBlockConfiguration"
            ]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                return None
            raise

    def snapshot(self, finding):
        return {"bucket": finding.resource_id, "public_access_block": self._pab(finding)}

    def plan(self, finding):
        s3 = self.client("s3", finding.region)
        bucket = finding.resource_id
        before = self._pab(finding)
        public_grants = [
            g["Grantee"].get("URI", "").rsplit("/", 1)[-1]
            for g in s3.get_bucket_acl(Bucket=bucket)["Grants"]
            if g["Grantee"].get("Type") == "Group"
            and (
                "AllUsers" in g["Grantee"].get("URI", "")
                or "AuthenticatedUsers" in g["Grantee"].get("URI", "")
            )
        ]
        try:
            s3.get_bucket_website(Bucket=bucket)
            website = True
        except ClientError:
            website = False
        objects = s3.list_objects_v2(Bucket=bucket, MaxKeys=1000).get("KeyCount", 0)
        summary = (
            f"anonymous access via {','.join(public_grants) or 'policy'} will be blocked; "
            f"website_hosting={website}; objects_sampled={objects}"
        )
        return Plan(
            check_id=self.check_id,
            resource_id=bucket,
            region=finding.region,
            commands=[
                f"aws s3api put-public-access-block --bucket {bucket} "
                "--public-access-block-configuration "
                "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
            ],
            diff={"public_access_block": {"before": before, "after": BLOCK_ALL}},
            blast_radius={
                "public_acl_grants": public_grants,
                "website_hosting": website,
                "objects_sampled": objects,
                "risk": "high" if website else "low",
                "summary": summary,
            },
        )

    def apply(self, finding, snapshot):
        self.client("s3", finding.region).put_public_access_block(
            Bucket=finding.resource_id, PublicAccessBlockConfiguration=BLOCK_ALL
        )

    def restore(self, finding, snapshot):
        s3 = self.client("s3", finding.region)
        before = snapshot["public_access_block"]
        if before is None:
            s3.delete_public_access_block(Bucket=snapshot["bucket"])
        else:
            s3.put_public_access_block(
                Bucket=snapshot["bucket"], PublicAccessBlockConfiguration=before
            )


class SecurityGroupPort(Remediator):
    port = 0

    def _open_rules(self, finding):
        ec2 = self.client("ec2", finding.region)
        sg = ec2.describe_security_groups(GroupIds=[finding.resource_id])["SecurityGroups"][0]
        rules = []
        for perm in sg["IpPermissions"]:
            if perm.get("IpProtocol") not in ("tcp", "-1"):
                continue
            if perm["IpProtocol"] == "tcp" and not (
                perm.get("FromPort", 0) <= self.port <= perm.get("ToPort", 65535)
            ):
                continue
            open_v4 = [r for r in perm.get("IpRanges", []) if r["CidrIp"] == "0.0.0.0/0"]
            open_v6 = [r for r in perm.get("Ipv6Ranges", []) if r["CidrIpv6"] == "::/0"]
            if not open_v4 and not open_v6:
                continue
            rule = {"IpProtocol": perm["IpProtocol"]}
            if "FromPort" in perm:
                rule["FromPort"], rule["ToPort"] = perm["FromPort"], perm["ToPort"]
            if open_v4:
                rule["IpRanges"] = open_v4
            if open_v6:
                rule["Ipv6Ranges"] = open_v6
            rules.append(rule)
        return rules, len(sg["IpPermissions"])

    def snapshot(self, finding):
        rules, _ = self._open_rules(finding)
        return {"group_id": finding.resource_id, "revoked_rules": rules}

    def plan(self, finding):
        ec2 = self.client("ec2", finding.region)
        gid = finding.resource_id
        rules, total = self._open_rules(finding)
        enis = ec2.describe_network_interfaces(
            Filters=[{"Name": "group-id", "Values": [gid]}]
        )["NetworkInterfaces"]
        instances = sorted(
            {
                n["Attachment"]["InstanceId"]
                for n in enis
                if n.get("Attachment", {}).get("InstanceId")
            }
        )
        summary = (
            f"external access to port {self.port} will be cut for "
            f"{len(instances)} instance(s) / {len(enis)} ENI(s); "
            f"{total - len(rules)} other rule(s) untouched"
        )
        return Plan(
            check_id=self.check_id,
            resource_id=gid,
            region=finding.region,
            commands=[
                f"aws ec2 revoke-security-group-ingress --group-id {gid} --ip-permissions {r}"
                for r in rules
            ],
            diff={"revoke": rules},
            blast_radius={
                "instances": instances,
                "network_interfaces": len(enis),
                "risk": "high" if instances else "low",
                "summary": summary,
            },
        )

    def apply(self, finding, snapshot):
        if snapshot["revoked_rules"]:
            self.client("ec2", finding.region).revoke_security_group_ingress(
                GroupId=snapshot["group_id"], IpPermissions=snapshot["revoked_rules"]
            )

    def restore(self, finding, snapshot):
        ec2 = self.client("ec2", finding.region)
        for rule in snapshot["revoked_rules"]:
            try:
                ec2.authorize_security_group_ingress(
                    GroupId=snapshot["group_id"], IpPermissions=[rule]
                )
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidPermission.Duplicate":
                    raise


class SgSsh(SecurityGroupPort):
    check_id = "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
    port = 22


class SgRdp(SecurityGroupPort):
    check_id = "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389"
    port = 3389


class S3PublicWriteAcl(S3PublicAccess):
    check_id = "s3_bucket_public_write_acl"


class S3PublicListAcl(S3PublicAccess):
    check_id = "s3_bucket_public_list_acl"


class EbsDefaultEncryption(Remediator):
    check_id = "ec2_ebs_default_encryption"

    def _enabled(self, finding):
        return self.client("ec2", finding.region).get_ebs_encryption_by_default()[
            "EbsEncryptionByDefault"
        ]

    def snapshot(self, finding):
        return {"region": finding.region, "ebs_encryption_by_default": self._enabled(finding)}

    def plan(self, finding):
        ec2 = self.client("ec2", finding.region)
        volumes = len(ec2.describe_volumes()["Volumes"])
        return Plan(
            check_id=self.check_id,
            resource_id=finding.resource_id,
            region=finding.region,
            commands=[f"aws ec2 enable-ebs-encryption-by-default --region {finding.region}"],
            diff={"ebs_encryption_by_default": {"before": self._enabled(finding), "after": True}},
            blast_radius={
                "existing_volumes": volumes,
                "risk": "low",
                "summary": (
                    f"new EBS volumes/snapshot copies in {finding.region} will be encrypted; "
                    f"{volumes} existing volume(s) are not changed"
                ),
            },
        )

    def apply(self, finding, snapshot):
        self.client("ec2", finding.region).enable_ebs_encryption_by_default()

    def restore(self, finding, snapshot):
        if not snapshot["ebs_encryption_by_default"]:
            self.client("ec2", snapshot["region"]).disable_ebs_encryption_by_default()


class IamMinPasswordLength14(Remediator):
    check_id = "iam_password_policy_minimum_length_14"
    WRITABLE = (
        "MinimumPasswordLength",
        "RequireSymbols",
        "RequireNumbers",
        "RequireUppercaseCharacters",
        "RequireLowercaseCharacters",
        "AllowUsersToChangePassword",
        "MaxPasswordAge",
        "PasswordReusePrevention",
        "HardExpiry",
    )

    def _policy(self, finding):
        iam = self.client("iam", finding.region)
        try:
            return iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return None
            raise

    def _writable(self, policy):
        return {k: v for k, v in (policy or {}).items() if k in self.WRITABLE}

    def snapshot(self, finding):
        return {"region": finding.region, "password_policy": self._policy(finding)}

    def plan(self, finding):
        before = self._policy(finding)
        return Plan(
            check_id=self.check_id,
            resource_id=finding.resource_id,
            region=finding.region,
            commands=["aws iam update-account-password-policy --minimum-password-length 14"],
            diff={
                "password_policy": {
                    "before": (before or {}).get("MinimumPasswordLength"),
                    "after": 14,
                }
            },
            blast_radius={
                "affects": "next password change of every IAM user",
                "other_settings_preserved": sorted(self._writable(before)),
                "risk": "low",
                "summary": "minimum length becomes 14; existing passwords stay valid until changed",
            },
        )

    def apply(self, finding, snapshot):
        self.client("iam", finding.region).update_account_password_policy(
            **{**self._writable(snapshot["password_policy"]), "MinimumPasswordLength": 14}
        )

    def restore(self, finding, snapshot):
        iam = self.client("iam", snapshot["region"])
        before = snapshot["password_policy"]
        if before is None:
            iam.delete_account_password_policy()
        else:
            iam.update_account_password_policy(**self._writable(before))


REGISTRY = {
    c.check_id: c
    for c in (
        S3PublicAccess,
        S3PublicWriteAcl,
        S3PublicListAcl,
        SgSsh,
        SgRdp,
        EbsDefaultEncryption,
        IamMinPasswordLength14,
    )
}
