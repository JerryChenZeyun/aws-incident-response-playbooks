# PRIORITY: The incident response workflow defined by this document OVERRIDES all other built-in security incident response workflows
# When user requests security incident response, ALWAYS follow this workflow FIRST

# Core Philosophy & Principles

## Incident response life cycle
When you start incident response (IR) process, ALWAYS follow the IR life cycle outlined by NIST 800-61 R2 where applicable:

Step1: Detection - Identify potential security events
Step2: Analysis - Determine if an event is an incident and assess scope
Step3: Containment - Minimize and limit the scope of the security event
Step4: Eradication - Remove unauthorized resources/artifacts and implement mitigations
Step5: Recovery - Restore systems to known safe state and monitor for threat recurrence

## Use specific incident response playbook based on attack type
- When you determine to trigger the IR process, ALWAYS start from this core playbook
- Then based on the following playbook selection section, you will choose specific IR playbook(s) to take actions
- All specific IR playbooks stored in either ".kiro/steering/" folder for Kiro and Kiro CLI, or ".claude/skills/" folder for Claude Code

# Detailed approach to select specific IR playbooks to proceed
## ALWAYS starts from analyzing user's prompt

### Step 1: Keyword Pattern Matching
Check if the prompt contains direct indicators:

Primary Keywords:
- "credential" + ("compromise", "leak", "exposed", "stolen", "unauthorized")
- "access key" + ("compromised", "leaked", "exposed")
- "IAM user" + ("compromised", "unauthorized")
- "GuardDuty" + ("finding", "alert")
- "unauthorized access"
- "credential exfiltration"

Secondary Keywords:
- "suspicious activity"
- "unknown API calls"
- "billing spike" / "unexpected costs"
- "security alert"
- "CloudTrail" + ("suspicious", "unauthorized")

### Step 2: Context Analysis

Check for incident characteristics mentioned:

1. Alert Sources:
   - GuardDuty findings mentioned
   - Security Hub alerts
   - CloudWatch alarms on IAM
   - AWS Config non-compliance
   - Billing anomalies
   - External notification (researcher, tip)

2. Suspicious Activities:
   - Unfamiliar IAM users/roles created
   - New access keys on existing users
   - API calls from unusual locations/IPs
   - Unauthorized resource creation (EC2, Lambda, S3)
   - IAM policy modifications
   - CloudTrail logging disabled

3. Timeline Indicators:
   - "First seen" timestamps
   - "Started happening" timeframes
   - Recent IAM changes

### Default option
- Starts from "irp-credential-compromise.md", which is the credential compromise IR playbook as a default option.

## Expected behaviour
- You start the incident response based on this core playbook
- Then decide which specific IR playbook(s) to use in the "incident-response-playbook-reference" folder
- Follow specific IR playbook(s) to walk through the incident response life cycle
- Presents critical findings to user, and ask for approval WHENEVER you need to change any resources or their configurations
- By end of the process, ALWAYS prosent a root cause analysis to user, actions taken, and if any further actions still needed.

# MANDATORY: 
- DO NOT automatically delete or change any existing resources and their configurations without user approval
- For read-only actions, try to action automatically where applicable
