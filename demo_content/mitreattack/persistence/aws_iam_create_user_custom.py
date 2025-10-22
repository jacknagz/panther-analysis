from panther_aws_helpers import aws_cloudtrail_success


def rule(event):
    return aws_cloudtrail_success(event) and event.get("eventName") == "CreateUser"


def title(event):
    actor_arn = event.deep_get("userIdentity", "arn", default="")
    created_user = event.deep_get("requestParameters", "userName", default="")

    # Extract meaningful actor name from ARN
    if ":assumed-role/" in actor_arn:
        # For assumed roles, get the role name and user
        role_part = actor_arn.split(":assumed-role/")[1]
        if "/" in role_part:
            role_name, session_name = role_part.split("/", 1)
            actor_display = f"assumed role {role_name} (session: {session_name})"
        else:
            actor_display = f"assumed role {role_part}"
    elif ":user/" in actor_arn:
        user_name = actor_arn.split(":user/")[1]
        actor_display = f"user {user_name}"
    elif ":root" in actor_arn:
        actor_display = "root account"
    else:
        actor_display = actor_arn

    return f"IAM user [{created_user}] created by [{actor_display}]"


def runbook(event):
    return f"""
Our security policy disallows the creation of IAM users. 
Follow these steps to assess the alert:
1. Check for suspicious follow-up activities, like admin IAM policy attachments or access key creation, within 1 hour of ({event.get("eventTime", "")}) in the aws_cloudtrail table.
2. Check if the created user still exists.
3. Check if this actor has a history of creating IAM users.
"""


def alert_context(event):
    context = {
        "created_user": event.deep_get("requestParameters", "userName", default=""),
        "actor": event.deep_get("userIdentity", "arn", default=""),
        "timestamp": event.get("p_event_time", ""),
        "parameters": event.deep_get("requestParameters", default={}),
        "action": event.get("eventName", ""),
    }
    return context
