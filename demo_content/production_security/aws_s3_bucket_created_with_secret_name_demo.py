from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context


def rule(event):
    if not aws_cloudtrail_success(event):
        return False

    # Check for CreateBucket event
    if event.get("eventName") != "CreateBucket":
        return False

    # Check if bucket name contains "secret"
    bucket_name = event.deep_get("requestParameters", "bucketName", default="")
    return "secret" in bucket_name.lower()


def title(event):
    bucket_name = event.deep_get("requestParameters", "bucketName", default="<UNKNOWN>")
    user = event.deep_get("userIdentity", "userName") or event.deep_get(
        "userIdentity",
        "sessionContext",
        "sessionIssuer",
        "userName",
        default="<UNKNOWN_USER>",
    )
    account_id = event.get("recipientAccountId", "<UNKNOWN_ACCOUNT>")

    return (
        f"S3 bucket with 'secret' in name created: '{bucket_name}' "
        f"by [{user}] in account [{account_id}]"
    )


def alert_context(event):
    return aws_rule_context(event)


def runbook(event):
    bucket_name = event.deep_get("requestParameters", "bucketName", default="<UNKNOWN>")
    user_arn = event.deep_get("userIdentity", "arn", default="<UNKNOWN_ARN>")

    return f"""
    1. Verify if the S3 bucket creation was authorized and follows naming standards
    2. Review the bucket name '{bucket_name}' to confirm it doesn't expose sensitive information
    3. Investigate the creating principal {user_arn} and their recent activity
    4. Check the bucket configuration for:
       - Public access settings
       - Encryption configuration
       - Versioning status
       - Logging enabled
    5. If unauthorized, delete the bucket and review IAM permissions
    6. If authorized but poorly named, consider renaming or implementing naming policies
    7. Review organizational bucket naming standards to prevent information leakage
    """
