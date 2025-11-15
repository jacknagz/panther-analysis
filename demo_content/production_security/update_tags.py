#!/usr/bin/env python3
"""
Script to update all production_security rules with TAG_TAXONOMY.md compliant tags.
This ensures every rule has at least one compliance tag and one usecase tag.
"""

import yaml
import os
from pathlib import Path

# Tag mapping based on rule type/purpose
TAG_MAPPINGS = {
    # EC2 Rules
    "aws_ec2_ebs_encryption_disabled": {
        "required": ["compliance.soc2", "compliance.iso27001", "usecase.configuration_management"],
        "optional": ["mitre.ta0005.defense_evasion", "asset.identity_management", "impact.confidentiality"]
    },
    "aws_ec2_gateway_modified": {
        "required": ["compliance.soc2", "usecase.configuration_management", "usecase.insider_threat_detection"],
        "optional": ["mitre.ta0005.defense_evasion", "mitre.ta0040.impact", "threat.insider", "impact.availability"]
    },
    "aws_ec2_instance_without_tags_demo": {
        "required": ["compliance.soc2", "usecase.configuration_management"],
        "optional": ["asset.identity_management"]
    },
    "aws_ec2_lambda_launched_demo": {
        "required": ["compliance.soc2", "usecase.configuration_management"],
        "optional": ["mitre.ta0002.execution", "asset.identity_management"]
    },
    "aws_ec2_manual_security_group_changes": {
        "required": ["compliance.soc2", "compliance.nist_csf", "usecase.configuration_management", "usecase.insider_threat_detection"],
        "optional": ["mitre.ta0005.defense_evasion", "threat.insider", "impact.confidentiality"]
    },
    "aws_ec2_many_passwords_read_attempts": {
        "required": ["compliance.soc2", "usecase.insider_threat_detection", "usecase.privileged_access_monitoring"],
        "optional": ["mitre.ta0006.credential_access", "mitre.t1110.brute_force", "threat.insider", "impact.confidentiality"]
    },
    "aws_ec2_monitoring": {
        "required": ["compliance.soc2", "usecase.configuration_management"],
        "optional": ["mitre.ta0005.defense_evasion", "mitre.t1562.impair_defenses", "asset.detection_controls", "impact.availability"]
    },
    "aws_ec2_startup_script_change": {
        "required": ["compliance.soc2", "usecase.configuration_management", "usecase.insider_threat_detection"],
        "optional": ["mitre.ta0002.execution", "mitre.t1059.command_and_scripting_interpreter", "threat.insider", "impact.integrity"]
    },

    # GuardDuty Rules
    "aws_guardduty_critical_sev_findings_demo": {
        "required": ["compliance.soc2", "compliance.nist_csf", "usecase.siem_integrity"],
        "optional": ["asset.detection_controls", "threat.external", "impact.confidentiality"]
    },
    "aws_guardduty_high_sev_findings_demo": {
        "required": ["compliance.soc2", "usecase.siem_integrity"],
        "optional": ["asset.detection_controls", "threat.external"]
    },
    "aws_guardduty_low_sev_findings_demo": {
        "required": ["compliance.soc2", "usecase.siem_integrity"],
        "optional": ["asset.detection_controls"]
    },
    "aws_guardduty_med_sev_findings_demo": {
        "required": ["compliance.soc2", "usecase.siem_integrity"],
        "optional": ["asset.detection_controls", "threat.external"]
    },

    # S3 Rules
    "aws_resource_made_public_demo": {
        "required": ["compliance.soc2", "compliance.nist_csf", "usecase.configuration_management", "usecase.insider_threat_detection"],
        "optional": ["mitre.ta0010.exfiltration", "mitre.t1537.transfer_data_to_cloud_account", "threat.insider", "impact.confidentiality"]
    },
    "aws_s3_large_download_specific_bucket_demo": {
        "required": ["compliance.soc2", "usecase.insider_threat_detection"],
        "optional": ["mitre.ta0010.exfiltration", "mitre.t1537.transfer_data_to_cloud_account", "threat.insider", "impact.confidentiality"]
    },
    "aws_s3_large_download_specific_bucket_query_demo": {
        "required": ["compliance.soc2", "usecase.insider_threat_detection"],
        "optional": ["mitre.ta0010.exfiltration", "threat.insider"]
    },
    "aws_s3_mass_exfiltration_deletion_demo": {
        "required": ["compliance.soc2", "usecase.insider_threat_detection"],
        "optional": ["mitre.ta0010.exfiltration", "mitre.ta0040.impact", "mitre.t1485.data_destruction", "threat.insider", "threat.external", "impact.availability", "impact.confidentiality"]
    },
    "s3_bucket_deleted_by_sso_role_us_west_2_demo": {
        "required": ["compliance.soc2", "usecase.insider_threat_detection", "usecase.privileged_access_monitoring"],
        "optional": ["mitre.ta0040.impact", "mitre.t1485.data_destruction", "threat.insider", "impact.availability"]
    },
    "s3_high_volume_getobject_cc_corp_secret_data_demo": {
        "required": ["compliance.soc2", "usecase.insider_threat_detection"],
        "optional": ["mitre.ta0010.exfiltration", "mitre.t1530.data_from_cloud_storage", "threat.insider", "impact.confidentiality"]
    },

    # Secrets Manager Rules
    "aws_secretsmanager_retrieve_secrets_catchall_demo": {
        "required": ["compliance.soc2", "usecase.insider_threat_detection", "usecase.privileged_access_monitoring"],
        "optional": ["mitre.ta0006.credential_access", "mitre.t1552.unsecured_credentials", "asset.api_credentials", "threat.insider", "impact.confidentiality"]
    },
    "aws_secretsmanager_retrieve_secrets_multiregion_demo": {
        "required": ["compliance.soc2", "usecase.insider_threat_detection", "usecase.privileged_access_monitoring"],
        "optional": ["mitre.ta0006.credential_access", "mitre.t1552.unsecured_credentials", "asset.api_credentials", "threat.insider", "impact.confidentiality"]
    },

    # IAM Rules
    "aws_iam_attach_admin_user_policy_demo": {
        "required": ["compliance.soc2", "compliance.iso27001", "usecase.privileged_access_monitoring", "usecase.insider_threat_detection"],
        "optional": ["mitre.ta0003.persistence", "mitre.ta0004.privilege_escalation", "mitre.t1078.valid_accounts", "asset.identity_management", "threat.insider", "impact.confidentiality"]
    },

    # Macie Rules
    "aws_macie_evasion_demo": {
        "required": ["compliance.soc2", "usecase.siem_integrity", "usecase.insider_threat_detection"],
        "optional": ["mitre.ta0005.defense_evasion", "mitre.t1562.impair_defenses", "asset.detection_controls", "threat.insider", "impact.availability"]
    },

    # GuardDuty Bitcoin Mining
    "aws_guardduty_bitcoin_mining_demo": {
        "required": ["compliance.soc2", "usecase.siem_integrity"],
        "optional": ["mitre.ta0040.impact", "mitre.t1496.resource_hijacking", "asset.detection_controls", "threat.external", "impact.availability"]
    },

    # S3 Access Rules
    "aws_s3_access_to_training_data_demo": {
        "required": ["compliance.soc2", "usecase.insider_threat_detection", "usecase.privileged_access_monitoring"],
        "optional": ["mitre.ta0009.collection", "mitre.t1530.data_from_cloud_storage", "threat.insider", "impact.confidentiality"]
    },

    # Secrets Manager Retrieve
    "aws_secretsmanager_retrieve_secrets_demo": {
        "required": ["compliance.soc2", "usecase.insider_threat_detection", "usecase.privileged_access_monitoring"],
        "optional": ["mitre.ta0006.credential_access", "mitre.t1552.unsecured_credentials", "mitre.ta0007.discovery", "asset.api_credentials", "threat.insider", "impact.confidentiality"]
    },

    # VPC Flow SSH
    "aws_vpcflow_successful_inbound_ssh_signal_demo": {
        "required": ["compliance.soc2", "usecase.authentication_monitoring"],
        "optional": ["mitre.ta0001.initial_access", "threat.external"]
    },

    # CloudTrail (already done manually but adding for completeness)
    "aws_cloudtrail_stopped_demo": {
        "required": ["compliance.soc2", "compliance.nist_csf", "usecase.siem_integrity", "usecase.insider_threat_detection"],
        "optional": ["mitre.ta0005.defense_evasion", "mitre.t1562.impair_defenses", "asset.logging_infrastructure", "asset.detection_controls", "threat.insider", "impact.availability"]
    },

    # Console login rules (already done manually)
    "aws_console_login_demo": {
        "required": ["compliance.soc2", "usecase.authentication_monitoring", "usecase.privileged_access_monitoring"],
        "optional": ["mitre.ta0001.initial_access", "mitre.t1078.valid_accounts", "asset.identity_management"]
    },
    "aws_console_login_without_mfa_demo": {
        "required": ["compliance.soc2", "compliance.iso27001", "usecase.authentication_monitoring", "usecase.privileged_access_monitoring"],
        "optional": ["mitre.ta0001.initial_access", "mitre.t1078.valid_accounts", "asset.identity_management", "threat.external"]
    },
    "aws_console_root_login_demo": {
        "required": ["compliance.soc2", "compliance.nist_csf", "usecase.privileged_access_monitoring", "usecase.authentication_monitoring"],
        "optional": ["mitre.ta0004.privilege_escalation", "mitre.t1078.valid_accounts", "asset.identity_management", "threat.insider", "threat.external"]
    },
    "aws_console_root_login_failed_demo": {
        "required": ["compliance.soc2", "compliance.nist_csf", "usecase.authentication_monitoring", "usecase.privileged_access_monitoring"],
        "optional": ["mitre.ta0006.credential_access", "mitre.t1110.brute_force", "asset.identity_management", "threat.external", "threat.automated"]
    },
    "aws_console_signin_demo": {
        "required": ["compliance.soc2", "usecase.authentication_monitoring"],
        "optional": ["mitre.ta0001.initial_access", "mitre.t1078.valid_accounts", "asset.identity_management"]
    },

    # EC2 Download Instance User Data (already done manually)
    "aws_ec2_download_instance_user_data": {
        "required": ["compliance.soc2", "usecase.insider_threat_detection", "usecase.configuration_management"],
        "optional": ["mitre.ta0007.discovery", "mitre.t1580.cloud_infrastructure_discovery", "asset.identity_management", "threat.insider", "impact.confidentiality"]
    },

    # SSM and other rules
    "aws_ssm_suspicious_sendcommand": {
        "required": ["compliance.soc2", "usecase.insider_threat_detection", "usecase.privileged_access_monitoring"],
        "optional": ["mitre.ta0006.credential_access", "mitre.t1552.unsecured_credentials", "threat.insider", "threat.external", "impact.confidentiality"]
    },
    "cross_region_activity_demo": {
        "required": ["compliance.soc2", "usecase.insider_threat_detection"],
        "optional": ["mitre.ta0007.discovery", "threat.insider", "threat.automated"]
    },
    "large_data_transfer_to_external_demo": {
        "required": ["compliance.soc2", "usecase.insider_threat_detection"],
        "optional": ["mitre.ta0010.exfiltration", "mitre.t1537.transfer_data_to_cloud_account", "threat.insider", "threat.external", "impact.confidentiality"]
    },
}


def update_rule_tags(yaml_file):
    """Update tags in a YAML file according to TAG_TAXONOMY.md"""
    file_path = Path(yaml_file)
    rule_name = file_path.stem

    # Skip if no mapping defined
    if rule_name not in TAG_MAPPINGS:
        print(f"⏭️  Skipping {rule_name} - no mapping defined")
        return False

    try:
        with open(yaml_file, 'r') as f:
            content = f.read()

        # Load YAML
        data = yaml.safe_load(content)

        # Get tag mapping
        mapping = TAG_MAPPINGS[rule_name]
        new_tags = ["# Required tags"] + mapping["required"] + ["# Optional tags"] + mapping["optional"]

        # Update or add Tags field
        data['Tags'] = new_tags

        # Write back with proper formatting
        with open(yaml_file, 'w') as f:
            # Write the YAML with custom formatting for tags
            lines = []
            for key, value in data.items():
                if key == 'Tags':
                    lines.append(f"{key}:")
                    for tag in value:
                        if tag.startswith("#"):
                            lines.append(f"  {tag}")
                        else:
                            lines.append(f"  - {tag}")
                elif isinstance(value, dict):
                    lines.append(f"{key}:")
                    lines.append(yaml.dump(value, default_flow_style=False, indent=2))
                elif isinstance(value, list):
                    lines.append(f"{key}:")
                    for item in value:
                        if isinstance(item, dict):
                            lines.append("  -")
                            for k, v in item.items():
                                lines.append(f"    {k}: {v}")
                        else:
                            lines.append(f"  - {item}")
                else:
                    lines.append(f"{key}: {value}")

            # Use original file write to preserve exact YAML structure
            # Simpler approach: just insert/replace Tags section
            pass

        # Alternative: Use string replacement for better control
        if 'Tags:' in content:
            # Replace existing Tags section
            import re
            # Find Tags section and replace it
            pattern = r'Tags:.*?(?=\n[A-Z]|\nReports:|\n$)'
            tags_yaml = "Tags:\n"
            for tag in new_tags:
                if tag.startswith("#"):
                    tags_yaml += f"  {tag}\n"
                else:
                    tags_yaml += f"  - {tag}\n"
            content = re.sub(pattern, tags_yaml, content, flags=re.DOTALL)
        else:
            # Insert Tags section after Severity or LogTypes
            tags_yaml = "\nTags:\n"
            for tag in new_tags:
                if tag.startswith("#"):
                    tags_yaml += f"  {tag}\n"
                else:
                    tags_yaml += f"  - {tag}\n"
            # Insert after Severity line
            content = content.replace('\nReports:', f'{tags_yaml}Reports:', 1)
            if '\nReports:' not in content:
                # Try after DedupPeriodMinutes or other fields
                insert_after = ['\nSeverity:', '\nDedupPeriodMinutes:', '\nThreshold:', '\nDescription:']
                for marker in insert_after:
                    if marker in content:
                        lines = content.split('\n')
                        for i, line in enumerate(lines):
                            if marker.strip(':') in line:
                                # Find next non-indented line
                                j = i + 1
                                while j < len(lines) and (lines[j].startswith(' ') or lines[j].strip() == ''):
                                    j += 1
                                lines.insert(j, tags_yaml.rstrip())
                                content = '\n'.join(lines)
                                break
                        break

        with open(yaml_file, 'w') as f:
            f.write(content)

        print(f"✅ Updated {rule_name}")
        return True

    except Exception as e:
        print(f"❌ Error updating {rule_name}: {e}")
        return False


def main():
    """Main execution"""
    script_dir = Path(__file__).parent
    yml_files = sorted(script_dir.glob("*.yml"))

    updated = 0
    skipped = 0
    errors = 0

    for yml_file in yml_files:
        result = update_rule_tags(yml_file)
        if result is True:
            updated += 1
        elif result is False:
            skipped += 1
        else:
            errors += 1

    print(f"\n📊 Summary:")
    print(f"  ✅ Updated: {updated}")
    print(f"  ⏭️  Skipped: {skipped}")
    print(f"  ❌ Errors: {errors}")


if __name__ == "__main__":
    main()
