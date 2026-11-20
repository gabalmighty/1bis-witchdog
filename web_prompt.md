# Witch Dog web security prompt

## GOAL

Test an approved web application. Find security risks and verify them with safe evidence.

Use deterministic tools and agent investigation together.

## INPUT

- Target: Exact authorized web origin.
- Mode: BASELINE or AGENTIC_VAPT.
- Engagement: Private rules-of-engagement JSON.
- Policy: checklists/webapp-vapt-v1.md.
- Identity policy: checklists/identity-authorization-v1.md.
- Evidence folder: Private local folder under .witchdog.

Use BASELINE only when the operator selects it.

Use AGENTIC_VAPT for an approved, isolated test environment.

## SCOPE

A URL does not grant permission to test a system.

The operator must approve the origin and permitted paths.

Active tests need synthetic data, a recovery snapshot, and a restricted network.

The agent must not set approval fields without operator evidence.

## STEPS

1. Read AGENTS.md and docs/vapt-execution.md.
2. Read the VAPT and identity checklists.
3. Identify the host, tools, and test limits.
4. Check the written engagement.
5. Create a private engagement draft if one is missing.
6. Run the deterministic baseline in approved scope.
7. Create an offline plan with tools/agent_plan.py.
8. Record missing test coverage in the ledger.
9. Check the installed ZAP version and plan syntax.
10. Run only the approved ZAP stage.
11. Ingest scanner data through tools/vapt.py.
12. Check synthetic roles with tools/vapt_authz.py when approved.
13. Review authorized source code and API routes.
14. Compare each sensitive operation with alternate routes.
15. Study JWT trust, role changes, tenant filters, and file access.
16. Test a hypothesis only with approved synthetic data.
17. Verify each candidate before you mark it as confirmed.
18. Use tools/vapt_report.py to build the private assessment.
19. Prepare source fixes and safe retest steps.

Use the commands in docs/vapt-execution.md.

The planner does not execute tests. It only creates proposed intents.

## GATES

A nonzero ZAP precheck is HELD. Never run direct autorun to bypass it.

A ZAP warning needs a valid report and matching runner receipt.

Treat a manually imported report as EXTERNAL_UNVERIFIED.

Do not count two checks of the same root URL as broad coverage.

Do not execute a destructive test, persistence, or credential theft.

Do not access real employee, financial, or client records.

Do not follow off-scope redirects or scan other systems.

Do not send raw HTTP bodies, session tokens, or credentials to an LLM.

Use a separate approval before you change target source code.

## OUTPUT

Give the engagement ID, approved scope, tool versions, and run times.

List each tested surface, method, role, result, and evidence reference.

Classify every finding as confirmed, suspected, or unknown.

Report ZAP warnings and all held stages.

Do not claim full VAPT or ASVS compliance without complete test evidence.

Keep the raw report in private storage. Use short and direct sentences.

## REFERENCES

- OWASP WSTG: https://wstg.owasp.org/v4.2/
- OWASP ASVS: https://asvs.owasp.org/
- OWASP ZAP: https://www.zaproxy.org/docs/automate/automation-framework/
- Witch Dog guide: docs/vapt-execution.md
