# AWS SSM SendCommand Detection - Design Notes

## Overview

This detection identifies potentially malicious use of AWS Systems Manager (SSM) `SendCommand` to execute shell scripts on EC2 instances. While SSM is a legitimate administration tool, attackers commonly abuse it to:

1. **Steal EC2 instance credentials** from the metadata service (IMDS)
2. **Execute reconnaissance commands** to understand the environment
3. **Establish persistence** by modifying instance configuration
4. **Exfiltrate data** from compromised instances

## Attack Technique Reference

**MITRE ATT&CK:** T1552.005 - Unsecured Credentials: Cloud Instance Metadata API

**Stratus Red Team Test:** [aws.credential-access.ec2-steal-instance-credentials](https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ec2-steal-instance-credentials/)

### Example Attack Flow

```
1. Attacker compromises AWS IAM credentials with ssm:SendCommand permissions
2. Uses SendCommand with AWS-RunShellScript to execute:
   curl 169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>/
3. Retrieves temporary EC2 instance credentials from IMDS
4. Uses stolen credentials from external IP to call AWS APIs
5. GuardDuty may detect this as InstanceCredentialExfiltration
```

## Detection Limitations

### Why We Can't See the Actual Command

AWS CloudTrail **intentionally hides** the command parameters in SSM SendCommand events:

```json
{
  "eventName": "SendCommand",
  "requestParameters": {
    "documentName": "AWS-RunShellScript",
    "parameters": "HIDDEN_DUE_TO_SECURITY_REASONS"  // Always hidden
  }
}
```

This is a security feature by AWS to prevent sensitive information (passwords, API keys, etc.) from being logged in CloudTrail.

### What We CAN Detect

Since we can't see command content, we focus on **behavioral indicators**:

1. **Document Type**: `AWS-RunShellScript` allows arbitrary shell command execution
2. **Target Count**: Single-instance targeting is more suspicious than bulk operations
3. **User Context**: Non-service accounts executing commands
4. **Command Output Retrieval**: Multiple `GetCommandInvocation` calls may indicate attacker verification

## False Positive Scenarios

### HIGH Risk of False Positives (Legitimate Use Cases)

#### 1. System Administration
```
- Troubleshooting individual instances
- Collecting logs or diagnostics
- Applying hotfixes to specific servers
- Testing configurations before fleet-wide rollout
```

**Mitigation**: Review user identity and timing. Is this a known admin during business hours?

#### 2. Automation Tools
```
- CI/CD pipelines deploying to single instances
- Configuration management (Ansible, Chef, Puppet)
- Monitoring agents collecting data
- Backup scripts
```

**Mitigation**: Create exceptions for known automation roles/users.

#### 3. AWS Services
```
- AWS Systems Manager itself
- AWS CloudWatch agents
- AWS Config remediation
- AWS Security Hub automated response
```

**Mitigation**: Detection automatically lowers severity to INFO for service principals.

#### 4. Security Tools
```
- Vulnerability scanners
- EDR agents
- Security automation (e.g., isolating compromised instances)
```

**Mitigation**: Whitelist known security tool identities.

### MEDIUM Risk of False Positives

#### 5. Development/Testing
```
- Developers testing SSM access in dev environments
- Running debug commands during incidents
- Performance testing individual instances
```

**Mitigation**: Consider environment-specific tuning (dev vs prod).

## Severity Logic

The detection uses **dynamic severity** to reduce false positives:

### MEDIUM (Default)
- Single instance targeted
- AWS-RunShellScript document
- Non-service user/role
- **Most likely to be malicious or require investigation**

### LOW
- **Multiple instances** targeted (2+)
- Indicates bulk/fleet operation
- More likely to be legitimate administration

### INFO
- **AWS service principal** (userAgent contains aws-systems-manager, etc.)
- **Service role** (principalId starts with AIDAI)
- Legitimate AWS automation

## Investigation Workflow

When this alert fires, follow these steps:

### 1. Verify User Identity and Context

```sql
-- Get user details and recent activity
SELECT 
  p_event_time,
  eventName,
  eventSource,
  userIdentity:arn as actor,
  sourceIPAddress,
  userAgent
FROM panther_logs.public.aws_cloudtrail
WHERE userIdentity:arn = '<alerted_user_arn>'
  AND p_event_time BETWEEN '<alert_time - 1 hour>' AND '<alert_time + 10 minutes>'
ORDER BY p_event_time
```

**Questions to answer:**
- Is this a known user/role?
- Is this their normal behavior?
- Is the source IP expected?
- Was this during business hours?

### 2. Check for Stolen Credentials Usage

The key indicator of credential theft is API calls from the **instance role** after the SendCommand:

```sql
-- Look for instance role usage from non-EC2 IPs
SELECT 
  p_event_time,
  eventName,
  eventSource,
  userIdentity:arn as actor,
  sourceIPAddress,
  errorCode
FROM panther_logs.public.aws_cloudtrail
WHERE p_event_time BETWEEN '<sendcommand_time>' AND '<sendcommand_time + 2 hours>'
  AND userIdentity:sessionContext:sessionIssuer:arn LIKE '%<instance-role-name>%'
  AND userIdentity:type = 'AssumedRole'
  -- Look for non-AWS source IPs
  AND NOT (
    sourceIPAddress LIKE '%.amazonaws.com'
    OR sourceIPAddress LIKE '10.%'
    OR sourceIPAddress LIKE '172.%'
    OR sourceIPAddress LIKE '192.168.%'
  )
ORDER BY p_event_time
```

**Red flags:**
- sts:GetCallerIdentity from public IP
- ec2:DescribeInstances from non-EC2 source
- Any API calls from geographic location different from EC2 region

### 3. Retrieve Command Output (If Possible)

Use AWS CLI to get the actual command that was executed:

```bash
aws ssm get-command-invocation \
  --command-id <command-id-from-alert> \
  --instance-id <instance-id-from-alert> \
  --region <region>
```

**Look for:**
- Commands containing `169.254.169.254` (IMDS)
- Commands containing `curl`, `wget`, `python`, `bash -i`
- Base64 encoded commands
- Network connections to external IPs

### 4. Check Instance IMDS Configuration

```bash
# Check if instance requires IMDSv2
aws ec2 describe-instances \
  --instance-ids <instance-id> \
  --query 'Reservations[0].Instances[0].MetadataOptions'
```

**Ideal configuration:**
```json
{
  "HttpTokens": "required",  // IMDSv2 only
  "HttpPutResponseHopLimit": 1,
  "HttpEndpoint": "enabled"
}
```

## Remediation

If credential theft is confirmed:

### Immediate Actions

1. **Revoke Instance Profile Session**
   ```bash
   # Force new credentials by restarting the instance (drastic)
   aws ec2 reboot-instances --instance-ids <instance-id>
   ```

2. **Block External API Calls from Instance Role**
   ```json
   // Add to role's trust policy
   {
     "Condition": {
       "StringEquals": {
         "aws:SourceVpc": "<your-vpc-id>"
       }
     }
   }
   ```

3. **Review All API Calls from Stolen Credentials**
   - Check for data exfiltration (s3:GetObject, etc.)
   - Check for privilege escalation attempts
   - Check for lateral movement

### Long-term Preventions

1. **Require IMDSv2**
   ```bash
   aws ec2 modify-instance-metadata-options \
     --instance-id <instance-id> \
     --http-tokens required \
     --http-endpoint enabled
   ```

2. **Implement SCPs to Restrict EC2 Role Permissions**
   ```json
   {
     "Effect": "Deny",
     "Action": [
       "iam:CreateUser",
       "iam:CreateAccessKey",
       "iam:AttachUserPolicy"
     ],
     "Resource": "*",
     "Condition": {
       "StringLike": {
         "aws:PrincipalArn": "arn:aws:iam::*:role/EC2-*"
       }
     }
   }
   ```

3. **Monitor for GuardDuty Findings**
   - Enable GuardDuty if not already active
   - Create alerts for `InstanceCredentialExfiltration.*` findings

4. **Restrict SSM SendCommand Permissions**
   - Use tag-based access control
   - Require MFA for SendCommand
   - Limit to specific documents/commands

## Tuning Recommendations

### Reduce False Positives

1. **Create allowlist for known automation**
   ```yaml
   InlineFilters:
     - KeyPath: userIdentity.arn
       Condition: IsNotIn
       Values:
         - arn:aws:iam::123456789012:role/Automation-Role
         - arn:aws:iam::123456789012:user/jenkins-user
   ```

2. **Exclude dev/test environments**
   ```yaml
   InlineFilters:
     - KeyPath: recipientAccountId
       Condition: IsNotIn
       Values:
         - "111111111111"  # dev account
         - "222222222222"  # test account
   ```

3. **Focus on sensitive production accounts**
   - Set severity higher for production accounts
   - Lower threshold for certain high-value instances

### Increase Detection Coverage

1. **Create correlation rule** (future enhancement)
   - Track SendCommand → instance role usage within time window
   - Alert when instance credentials used from non-EC2 IP

2. **Add behavioral analytics**
   - Baseline normal SSM usage per user
   - Alert on deviation from baseline

3. **Integrate with GuardDuty**
   - Cross-reference with `InstanceCredentialExfiltration` findings
   - Auto-escalate when both detections fire

## Related Detections

This detection works best as part of a layered defense:

1. **AWS.SSM.DistributedCommand** - Bulk SSM command execution (different threat)
2. **AWS.GuardDuty.InstanceCredentialExfiltration** - Native AWS detection for stolen credentials
3. **AWS.EC2.ModifyInstanceMetadataOptions** - Detect IMDSv2 being disabled
4. **AWS.IAM.AssumeRole.UnusualLocation** - Geographic anomalies in role usage

## References

- [Stratus Red Team - EC2 Steal Instance Credentials](https://stratus-red-team.cloud/attack-techniques/AWS/aws.credential-access.ec2-steal-instance-credentials/)
- [AWS GuardDuty - InstanceCredentialExfiltration](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html#unauthorizedaccess-iam-instancecredentialexfiltrationoutsideaws)
- [HackingTheCloud - Steal EC2 Keys Undetected](https://hackingthe.cloud/aws/avoiding-detection/steal-keys-undetected/)
- [AWS Systems Manager SendCommand API](https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_SendCommand.html)
- [AWS IMDSv2 Best Practices](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)

