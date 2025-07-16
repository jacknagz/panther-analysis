from panther_aws_helpers import aws_cloudtrail_success, aws_rule_context
from panther_detection_helpers.caching import add_to_string_set

RULE_ID = "AWS.SecretsManager.RetrieveSecrets"
THRESHOLD = 7  # Lucky number 7 for unique secrets
TIME_WINDOW_MINUTES = 60


def rule(event):
    if event.get("eventName") != "GetSecretValue" and not aws_cloudtrail_success(event):
        return False

    user = event.deep_get("userIdentity", "arn")
    secret_arn = event.deep_get("requestParameters", "secretId")
    if not user or not secret_arn:
        return False

    cache_key = f"{RULE_ID}-{user}"
    unique_secrets = add_to_string_set(
        cache_key, secret_arn, event.event_time_epoch() + TIME_WINDOW_MINUTES * 60
    )
    if isinstance(unique_secrets, str):
        import json

        unique_secrets = json.loads(unique_secrets)
    elif not isinstance(unique_secrets, list):
        unique_secrets = []

    return len(unique_secrets) >= THRESHOLD


def title(event):
    user = event.deep_get("userIdentity", "arn")
    return (
        f"[{user}] attempted to retrieve a large number of unique secrets from AWS Secrets Manager"
    )


def alert_context(event):
    return aws_rule_context(event) | {
        "errorCode": event.get("errorCode"),
        "errorMessage": event.get("errorMessage"),
    }
