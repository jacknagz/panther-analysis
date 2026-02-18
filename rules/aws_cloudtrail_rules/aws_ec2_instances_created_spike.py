from panther_core import PantherEvent


def rule(event: PantherEvent) -> bool:
    """
    Scheduled rule that fires when an abnormally high volume of EC2 instances
    are created within an hour.

    The query detects spikes by comparing recent activity against a 7-day baseline
    using statistical analysis (3 standard deviations above the mean).
    """
    # The query only returns results when an anomaly is detected
    # So if we receive an event from the query, it means a spike was found
    return True


def title(event: PantherEvent) -> str:
    """Generate an alert title with key details about the spike."""
    account_id = event.get("recipientAccountId", "<UNKNOWN_ACCOUNT>")
    user_arn = event.get("user_arn", "<UNKNOWN_USER>")
    count = event.get("recent_instance_count", 0)
    anomaly_reason = event.get("anomaly_reason", "Anomaly detected")

    return (
        f"Abnormal EC2 instance creation spike detected: {count} instances "
        f"created by {user_arn} in account {account_id} - {anomaly_reason}"
    )


def severity(event: PantherEvent) -> str:
    """Adjust severity based on the volume of instances created."""
    count = event.get("recent_instance_count", 0)

    # Very high volume (>50 instances) is critical
    if count > 50:
        return "CRITICAL"
    # High volume (>30 instances) is high
    elif count > 30:
        return "HIGH"
    # Medium volume (>20 instances) is medium
    elif count > 20:
        return "MEDIUM"
    # Otherwise default severity from the rule definition
    return "DEFAULT"


def alert_context(event: PantherEvent) -> dict:
    """Provide additional context for the alert."""
    return {
        "account_id": event.get("recipientAccountId"),
        "user_arn": event.get("user_arn"),
        "principal_id": event.get("principal_id"),
        "instance_count": event.get("recent_instance_count"),
        "instance_types": event.get("instance_types", []),
        "source_ips": event.get("source_ips", []),
        "time_period": event.get("time_slice"),
        "baseline_avg": event.get("avg_instances"),
        "baseline_stddev": event.get("stddev_instances"),
        "anomaly_reason": event.get("anomaly_reason"),
    }
