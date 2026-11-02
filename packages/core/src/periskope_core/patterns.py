"""Patterns shared by the checks (which read) and the fixes (which write), so both agree on what they mean."""
import re

# A CI/CD variable whose name says it carries a secret.
SECRETISH = re.compile(r"TOKEN|PASSWORD|PASSWD|SECRET|API_?KEY|PRIVATE_?KEY|CREDENTIAL", re.IGNORECASE)
