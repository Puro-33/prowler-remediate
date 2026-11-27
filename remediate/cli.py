import os

from remediate.advisor import load_advisor
from remediate.pipeline import remediate, write_json
from remediate.scanner import failing

REGION = "us-east-1"


def sandbox_env():
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ.pop("AWS_PROFILE", None)
    os.environ["AWS_DEFAULT_REGION"] = REGION


def seed(kind, client):
    if kind == "s3":
        s3 = client("s3", REGION)
        s3.create_bucket(Bucket="demo-public-bucket")
        s3.put_bucket_acl(Bucket="demo-public-bucket", ACL="public-read")
        s3.put_public_access_block(
            Bucket="demo-public-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        return "s3_bucket_public_access"
    if kind in ("s3-write", "s3-list"):
        s3 = client("s3", REGION)
        s3.create_bucket(Bucket="demo-public-bucket")
        all_users = 'uri="http://acs.amazonaws.com/groups/global/AllUsers"'
        s3.put_bucket_acl(
            Bucket="demo-public-bucket",
            **({"GrantWrite": all_users} if kind == "s3-write" else {"GrantRead": all_users}),
        )
        s3.put_public_access_block(
            Bucket="demo-public-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        return "s3_bucket_public_write_acl" if kind == "s3-write" else "s3_bucket_public_list_acl"
    if kind == "ebs":
        client("ec2", REGION).create_volume(AvailabilityZone=f"{REGION}a", Size=1)
        return "ec2_ebs_default_encryption"
    if kind == "iam-length":
        client("iam", REGION).update_account_password_policy(
            MinimumPasswordLength=8, RequireSymbols=True, MaxPasswordAge=90
        )
        return "iam_password_policy_minimum_length_14"
    port = 22 if kind == "ssh" else 3389
    ec2 = client("ec2", REGION)
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg = ec2.create_security_group(GroupName="demo-sg", Description="demo", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": port,
                "ToPort": port,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    return f"ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_{port}"


def demo(kind, approve=False, advisor_kind="rules", out="remediate_result.json"):
    from boto3 import client
    from moto import mock_aws

    sandbox_env()
    with mock_aws():
        check_id = seed(kind, client)
        found = failing(check_id, [REGION])
        res = remediate(
            found[0], client, [REGION], approve=approve, advisor=load_advisor(advisor_kind)
        )
    write_json(res, out)
    return res
