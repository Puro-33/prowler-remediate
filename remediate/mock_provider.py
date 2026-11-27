# Adapted from tests/providers/aws/utils.py in https://github.com/prowler-cloud/prowler
# (Apache-2.0, Copyright Prowler contributors). That helper is not shipped in the PyPI
# package, so this is a trimmed copy: a moto-backed AwsProvider with a fixed fake identity.
from argparse import Namespace

from boto3 import session
from moto import mock_aws

from prowler.config.config import (
    default_config_file_path,
    default_fixer_config_file_path,
    get_default_mute_file_path,
)
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"


def _default_arguments(arguments, status):
    arguments.status = status
    arguments.output_formats = []
    arguments.output_directory = ""
    arguments.verbose = False
    arguments.only_logs = False
    arguments.unix_timestamp = False
    arguments.shodan = None
    arguments.security_hub = False
    arguments.send_sh_only_fails = False
    arguments.config_file = default_config_file_path
    arguments.fixer_config = default_fixer_config_file_path
    arguments.mutelist_file = get_default_mute_file_path("aws")
    return arguments


@mock_aws
def set_mocked_aws_provider(audited_regions):
    if not audited_regions:
        raise ValueError("pass an explicit list of regions")
    _default_arguments(Namespace(), [])
    audit_session = session.Session(profile_name=None, botocore_session=None)
    provider = AwsProvider()
    session_config = AwsProvider.set_session_config(None)
    provider._session.session_config = session_config
    provider._session.original_session = None
    provider._session.current_session = audit_session
    audit_session._session.set_default_client_config(session_config)
    provider._identity.account = AWS_ACCOUNT_NUMBER
    provider._identity.account_arn = AWS_ACCOUNT_ARN
    provider._identity.user_id = None
    provider._identity.partition = "aws"
    provider._identity.identity_arn = None
    provider._identity.profile = None
    provider._identity.profile_region = None
    provider._identity.audited_regions = audited_regions
    provider._scan_unused_services = True
    provider._enabled_regions = set(audited_regions)
    provider._organizations_metadata = None
    provider._audit_resources = []
    provider._audit_config = {}
    provider._fixer_config = {}
    provider._mutelist = None
    provider.audit_metadata = Audit_Metadata(
        services_scanned=0,
        expected_checks=[],
        completed_checks=0,
        audit_progress=0,
    )
    return provider
