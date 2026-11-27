import json
import os

import pytest
from boto3 import client
from moto import mock_aws

from remediate.advisor import LLMAdvisor, RuleAdvisor, load_advisor
from remediate.cli import REGION, sandbox_env, seed
from remediate.models import Finding
from remediate.pipeline import remediate, write_json
from remediate.remediators import REGISTRY, S3PublicAccess, SgSsh
from remediate.scanner import failing, scan

BUCKET = "demo-public-bucket"


@pytest.fixture(autouse=True)
def env():
    sandbox_env()


def pab_state():
    return client("s3", REGION).get_public_access_block(Bucket=BUCKET)[
        "PublicAccessBlockConfiguration"
    ]


def sg_rules(gid):
    return client("ec2", REGION).describe_security_groups(GroupIds=[gid])["SecurityGroups"][0][
        "IpPermissions"
    ]


class BrokenS3(S3PublicAccess):
    def apply(self, finding, snapshot):
        self.client("s3", finding.region).put_public_access_block(
            Bucket=finding.resource_id,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": False,
            },
        )


class RaisingS3(S3PublicAccess):
    def apply(self, finding, snapshot):
        super().apply(finding, snapshot)
        raise RuntimeError("boom after change")


@mock_aws
def test_s3_detected_as_fail():
    check = seed("s3", client)
    found = failing(check, [REGION])
    assert [f.resource_id for f in found] == [BUCKET]


@mock_aws
def test_s3_dry_run_changes_nothing():
    check = seed("s3", client)
    before = pab_state()
    f = failing(check, [REGION])[0]
    res = remediate(f, client, [REGION], approve=False)
    assert res.outcome == "dry-run"
    assert pab_state() == before
    assert res.plan["commands"] and res.plan["blast_radius"]["public_acl_grants"] == ["AllUsers"]
    assert "snapshot" not in res.timings and "apply" not in res.timings


@mock_aws
def test_s3_approve_fixes_and_verify_passes():
    check = seed("s3", client)
    f = failing(check, [REGION])[0]
    res = remediate(f, client, [REGION], approve=True)
    assert res.outcome == "fixed"
    assert all(pab_state().values())
    assert failing(check, [REGION]) == []
    assert set(res.timings) == {"plan", "snapshot", "apply", "verify"}
    assert res.total_seconds >= sum(res.timings.values()) - 0.01


@mock_aws
def test_s3_verify_fails_then_rollback_restores_original():
    check = seed("s3", client)
    before = pab_state()
    f = failing(check, [REGION])[0]
    res = remediate(f, client, [REGION], approve=True, remediator=BrokenS3(client))
    assert res.outcome == "rolled_back"
    assert "rollback" in res.timings
    assert pab_state() == before
    assert len(failing(check, [REGION])) == 1


@mock_aws
def test_s3_exception_during_apply_triggers_rollback():
    check = seed("s3", client)
    before = pab_state()
    f = failing(check, [REGION])[0]
    res = remediate(f, client, [REGION], approve=True, remediator=RaisingS3(client))
    assert res.outcome == "rolled_back"
    assert "boom" in res.error
    assert pab_state() == before


@mock_aws
def test_s3_rollback_when_no_pab_existed_deletes_it():
    s3 = client("s3", REGION)
    s3.create_bucket(Bucket=BUCKET)
    s3.put_bucket_acl(Bucket=BUCKET, ACL="public-read")
    f = failing("s3_bucket_public_access", [REGION])[0]
    rem = BrokenS3(client)
    snap = rem.snapshot(f)
    assert snap["public_access_block"] is None
    rem.apply(f, snap)
    rem.restore(f, snap)
    with pytest.raises(Exception):
        s3.get_public_access_block(Bucket=BUCKET)


@pytest.mark.parametrize("kind,port", [("ssh", 22), ("rdp", 3389)])
@mock_aws
def test_sg_full_loop(kind, port):
    check = seed(kind, client)
    f = failing(check, [REGION])[0]
    gid = f.resource_id
    res = remediate(f, client, [REGION], approve=True)
    assert res.outcome == "fixed"
    assert sg_rules(gid) == []
    assert failing(check, [REGION]) == []


@mock_aws
def test_sg_keeps_other_rules_and_rolls_back_exactly():
    check = seed("ssh", client)
    f = failing(check, [REGION])[0]
    ec2 = client("ec2", REGION)
    ec2.authorize_security_group_ingress(
        GroupId=f.resource_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    before = sg_rules(f.resource_id)

    class NoopSg(SgSsh):
        def apply(self, finding, snapshot):
            super().apply(finding, snapshot)
            ec2.authorize_security_group_ingress(
                GroupId=finding.resource_id,
                IpPermissions=[
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            )

    res = remediate(f, client, [REGION], approve=True, remediator=NoopSg(client))
    assert res.outcome == "rolled_back"
    ports = sorted(p["FromPort"] for p in sg_rules(f.resource_id))
    assert ports == sorted(p["FromPort"] for p in before) == [22, 443]


@mock_aws
def test_sg_plan_blast_radius_counts_instances():
    check = seed("ssh", client)
    f = failing(check, [REGION])[0]
    ec2 = client("ec2", REGION)
    vpc = ec2.describe_security_groups(GroupIds=[f.resource_id])["SecurityGroups"][0]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    ami = ec2.describe_images()["Images"][0]["ImageId"]
    ec2.run_instances(
        ImageId=ami, MinCount=1, MaxCount=1, SubnetId=subnet, SecurityGroupIds=[f.resource_id]
    )
    plan = SgSsh(client).plan(f)
    assert len(plan.blast_radius["instances"]) == 1
    assert plan.blast_radius["risk"] == "high"


@mock_aws
def test_clean_resource_is_not_a_finding():
    s3 = client("s3", REGION)
    s3.create_bucket(Bucket="private-bucket")
    s3.put_public_access_block(
        Bucket="private-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    assert [f.status for f in scan("s3_bucket_public_access", [REGION])] == ["PASS"]


def test_finding_from_json_roundtrip():
    d = {"check_id": "x", "resource_id": "r", "region": "us-east-1", "status": "FAIL"}
    assert Finding.from_dict(json.loads(json.dumps(d))).resource_id == "r"


def test_advisor_defaults_to_rules_without_llm_config(monkeypatch):
    monkeypatch.delenv("REMEDIATE_LLM_FUNC", raising=False)
    assert isinstance(load_advisor("llm"), RuleAdvisor)
    assert isinstance(load_advisor("rules"), RuleAdvisor)


def test_llm_advisor_uses_injected_callable_only():
    seen = []
    adv = LLMAdvisor(lambda prompt: seen.append(prompt) or "ok")
    assert adv.advise({"blast_radius": {}}) == "llm: ok" and len(seen) == 1


def test_registry_covers_seven_checks():
    assert len(REGISTRY) == 7


@mock_aws
def test_result_json_written_with_timings(tmp_path):
    check = seed("s3", client)
    f = failing(check, [REGION])[0]
    res = remediate(f, client, [REGION], approve=True)
    out = tmp_path / "r.json"
    write_json(res, out)
    data = json.loads(out.read_text(encoding="utf8"))
    assert data["outcome"] == "fixed" and data["total_seconds"] > 0
    assert data["snapshot"]["bucket"] == BUCKET


def test_no_real_credentials_used():
    assert os.environ["AWS_ACCESS_KEY_ID"] == "testing"
