import pytest
from boto3 import client
from moto import mock_aws

from remediate.cli import REGION, sandbox_env, seed
from remediate.pipeline import remediate
from remediate.remediators import (
    REGISTRY,
    EbsDefaultEncryption,
    IamMinPasswordLength14,
)
from remediate.scanner import CHECKS, failing

BUCKET = "demo-public-bucket"


@pytest.fixture(autouse=True)
def env():
    sandbox_env()


def pab():
    return client("s3", REGION).get_public_access_block(Bucket=BUCKET)[
        "PublicAccessBlockConfiguration"
    ]


def policy():
    return client("iam", REGION).get_account_password_policy()["PasswordPolicy"]


def test_every_registered_check_is_scannable():
    assert set(REGISTRY) == set(CHECKS)


@pytest.mark.parametrize("kind", ["s3-write", "s3-list"])
@mock_aws
def test_s3_acl_variants_full_loop(kind):
    check = seed(kind, client)
    f = failing(check, [REGION])[0]
    assert f.resource_id == BUCKET
    dry = remediate(f, client, [REGION], approve=False)
    assert dry.outcome == "dry-run" and not any(pab().values())
    res = remediate(f, client, [REGION], approve=True)
    assert res.outcome == "fixed"
    assert all(pab().values())
    assert failing(check, [REGION]) == []


@mock_aws
def test_ebs_default_encryption_full_loop_and_rollback():
    check = seed("ebs", client)
    ec2 = client("ec2", REGION)
    assert ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"] is False
    f = failing(check, [REGION])[0]
    dry = remediate(f, client, [REGION], approve=False)
    assert dry.outcome == "dry-run"
    assert dry.plan["blast_radius"]["existing_volumes"] == 1
    assert ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"] is False
    res = remediate(f, client, [REGION], approve=True)
    assert res.outcome == "fixed"
    assert ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"] is True
    assert failing(check, [REGION]) == []

    rem = EbsDefaultEncryption(client)
    rem.restore(f, res.snapshot)
    assert ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"] is False


class NoopIam(IamMinPasswordLength14):
    def apply(self, finding, snapshot):
        pass


@mock_aws
def test_iam_length_fix_keeps_other_settings():
    check = seed("iam-length", client)
    f = failing(check, [REGION])[0]
    res = remediate(f, client, [REGION], approve=True)
    assert res.outcome == "fixed"
    p = policy()
    assert p["MinimumPasswordLength"] == 14
    assert p["RequireSymbols"] is True and p["MaxPasswordAge"] == 90
    assert failing(check, [REGION]) == []


@mock_aws
def test_iam_length_verify_fails_then_rolls_back_exactly():
    check = seed("iam-length", client)
    before = policy()
    f = failing(check, [REGION])[0]
    res = remediate(f, client, [REGION], approve=True, remediator=NoopIam(client))
    assert res.outcome == "rolled_back"
    assert policy() == before
