import importlib
from unittest import mock

from remediate.models import Finding

CHECKS = {
    "s3_bucket_public_access": {
        "service": "s3",
        "clients": {
            "s3_client": ("prowler.providers.aws.services.s3.s3_service", "S3"),
            "s3control_client": ("prowler.providers.aws.services.s3.s3_service", "S3Control"),
        },
    },
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": {
        "service": "ec2",
        "clients": {
            "ec2_client": ("prowler.providers.aws.services.ec2.ec2_service", "EC2"),
            "vpc_client": ("prowler.providers.aws.services.vpc.vpc_service", "VPC"),
        },
    },
    "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389": {
        "service": "ec2",
        "clients": {
            "ec2_client": ("prowler.providers.aws.services.ec2.ec2_service", "EC2"),
            "vpc_client": ("prowler.providers.aws.services.vpc.vpc_service", "VPC"),
        },
    },
    "s3_bucket_public_write_acl": {
        "service": "s3",
        "clients": {
            "s3_client": ("prowler.providers.aws.services.s3.s3_service", "S3"),
            "s3control_client": ("prowler.providers.aws.services.s3.s3_service", "S3Control"),
        },
    },
    "s3_bucket_public_list_acl": {
        "service": "s3",
        "clients": {
            "s3_client": ("prowler.providers.aws.services.s3.s3_service", "S3"),
            "s3control_client": ("prowler.providers.aws.services.s3.s3_service", "S3Control"),
        },
    },
    "ec2_ebs_default_encryption": {
        "service": "ec2",
        "clients": {
            "ec2_client": ("prowler.providers.aws.services.ec2.ec2_service", "EC2"),
        },
    },
    "iam_password_policy_minimum_length_14": {
        "service": "iam",
        "clients": {
            "iam_client": ("prowler.providers.aws.services.iam.iam_service", "IAM"),
        },
    },
}


def check_module_path(check_id):
    service = CHECKS[check_id]["service"]
    return f"prowler.providers.aws.services.{service}.{check_id}.{check_id}"


def _build_provider(regions):
    from remediate.mock_provider import set_mocked_aws_provider

    return set_mocked_aws_provider(regions)


def scan(check_id, regions):
    spec = CHECKS[check_id]
    path = check_module_path(check_id)
    provider = _build_provider(regions)
    importlib.import_module(path)
    patches = [
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=provider,
        )
    ]
    for attr, (mod, cls) in spec["clients"].items():
        service_cls = getattr(importlib.import_module(mod), cls)
        patches.append(mock.patch(f"{path}.{attr}", new=service_cls(provider)))
    for p in patches:
        p.start()
    try:
        check = getattr(importlib.import_module(path), check_id)()
        reports = check.execute()
    finally:
        for p in reversed(patches):
            p.stop()
    return [
        Finding(
            check_id=check_id,
            resource_id=r.resource_id,
            region=r.region,
            status=r.status,
            resource_arn=getattr(r, "resource_arn", ""),
            status_extended=r.status_extended,
        )
        for r in reports
    ]


def failing(check_id, regions):
    return [f for f in scan(check_id, regions) if f.status == "FAIL"]
