"""Create persistent RDNA AWS fixtures for the Lemur sandbox task suite."""

import argparse
import json
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

ACCOUNT = "145023129460"
STACK_NAME = "lemur-sandbox-test"
BASELINE_CERTIFICATE_NAME = "lemur-test-baseline"
CLOUDFRONT_CERTIFICATE_NAME = "lemur-test-cloudfront-primary"
CLOUDFRONT_BACKUP_CERTIFICATE_NAME = "lemur-test-cloudfront-backup"


def read(path):
    return Path(path).read_text()


def account_id(session):
    return session.client("sts").get_caller_identity()["Account"]


def server_certificate(iam, name, path, certificate, private_key, chain):
    try:
        response = iam.get_server_certificate(ServerCertificateName=name)
        return response["ServerCertificate"]["ServerCertificateMetadata"]
    except iam.exceptions.NoSuchEntityException:
        response = iam.upload_server_certificate(
            Path=path,
            ServerCertificateName=name,
            CertificateBody=certificate,
            PrivateKey=private_key,
            CertificateChain=chain,
        )
        return response["ServerCertificateMetadata"]


def stack_parameters(baseline, cloudfront, alias):
    return [
        {
            "ParameterKey": "BaselineCertificateArn",
            "ParameterValue": baseline["Arn"],
        },
        {
            "ParameterKey": "CloudFrontCertificateId",
            "ParameterValue": cloudfront["ServerCertificateId"],
        },
        {"ParameterKey": "CloudFrontAlias", "ParameterValue": alias},
    ]


def upsert_stack(cloudformation, template, parameters, replace):
    existing = False
    try:
        cloudformation.describe_stacks(StackName=STACK_NAME)
        existing = True
    except ClientError as error:
        if "does not exist" not in str(error):
            raise

    if existing and replace:
        cloudformation.delete_stack(StackName=STACK_NAME)
        cloudformation.get_waiter("stack_delete_complete").wait(StackName=STACK_NAME)
        existing = False

    if existing:
        try:
            cloudformation.update_stack(
                StackName=STACK_NAME,
                TemplateBody=template,
                Parameters=parameters,
            )
            cloudformation.get_waiter("stack_update_complete").wait(
                StackName=STACK_NAME
            )
        except ClientError as error:
            if "No updates are to be performed" not in str(error):
                raise
    else:
        cloudformation.create_stack(
            StackName=STACK_NAME,
            TemplateBody=template,
            Parameters=parameters,
            OnFailure="DELETE",
            Tags=[{"Key": "lemur-test", "Value": "persistent-fixture"}],
        )
        cloudformation.get_waiter("stack_create_complete").wait(StackName=STACK_NAME)

    stack = cloudformation.describe_stacks(StackName=STACK_NAME)["Stacks"][0]
    return {item["OutputKey"]: item["OutputValue"] for item in stack["Outputs"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--certificate-chain", required=True)
    parser.add_argument("--replacement-certificate", required=True)
    parser.add_argument("--replacement-private-key", required=True)
    parser.add_argument("--replacement-certificate-chain", required=True)
    parser.add_argument("--cloudfront-alias", required=True)
    parser.add_argument("--profile")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Delete and recreate the fixture stack before applying it.",
    )
    args = parser.parse_args()

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    actual_account = account_id(session)
    if actual_account != ACCOUNT:
        raise RuntimeError(
            "Refusing to modify AWS account {}, expected RDNA account {}".format(
                actual_account, ACCOUNT
            )
        )

    certificate = read(args.certificate)
    private_key = read(args.private_key)
    chain = read(args.certificate_chain)
    replacement_certificate = read(args.replacement_certificate)
    replacement_private_key = read(args.replacement_private_key)
    replacement_chain = read(args.replacement_certificate_chain)
    if certificate == replacement_certificate:
        raise RuntimeError(
            "CloudFront primary and replacement certificates must be distinct"
        )
    iam = session.client("iam")
    baseline = server_certificate(
        iam,
        BASELINE_CERTIFICATE_NAME,
        "/lemur-test/",
        certificate,
        private_key,
        chain,
    )
    cloudfront = server_certificate(
        iam,
        CLOUDFRONT_CERTIFICATE_NAME,
        "/cloudfront/",
        certificate,
        private_key,
        chain,
    )
    server_certificate(
        iam,
        CLOUDFRONT_BACKUP_CERTIFICATE_NAME,
        "/cloudfront/",
        replacement_certificate,
        replacement_private_key,
        replacement_chain,
    )

    template = read(Path(__file__).with_name("lemur-test-aws.yaml"))
    outputs = upsert_stack(
        session.client("cloudformation"),
        template,
        stack_parameters(baseline, cloudfront, args.cloudfront_alias),
        args.replace,
    )
    print(json.dumps(outputs, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
