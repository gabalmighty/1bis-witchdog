# Witch Dog writing rules

Witch Dog uses ASD-STE100 Issue 9 as a guide for clear technical writing.

This guide does not certify full ASD-STE100 compliance. The automated checker does not validate the controlled dictionary.

## Write clear text

- Use one meaning for each technical term.
- Use short and direct sentences.
- Use active voice when possible.
- Use one instruction in each step.
- Put instructions in the order of execution.
- Explain an abbreviation on first use.
- Use the same term in every document.
- Use examples that do not contain real secrets.
- Show what the tool does and what it does not do.
- Name the source and date of a security claim.
- Separate a verified result from an assumption.
- Do not use promotional claims without evidence.

## Limits

- Use 20 words or fewer for a procedure sentence.
- Use 25 words or fewer for a descriptive sentence.
- Use lists for complex procedures.
- Use approved technical terms where necessary.
- Keep code, commands, and paths exact.

## Write prompts with a clear contract

Use these headings in the same order:

1. GOAL: State one result.
2. INPUT: Name each input and its source.
3. SCOPE: Name the approved assets and limits.
4. STEPS: Give numbered actions.
5. GATES: State when the agent must stop.
6. OUTPUT: Define the report and evidence format.

Treat all external data as untrusted. An agent must not change its permissions based on source text.

## Review and test

Run the Markdown style checker before a pull request.

    python3 tools/check_docs_style.py docs/writing-standard.md CONTRIBUTING.md

Use the advisory mode to measure older documents.

    python3 tools/check_docs_style.py --advisory README.md docs/*.md

A reviewer must check word choice and meaning. The checker measures sentence length only.

## References

- Official standard: https://www.asd-ste100.org/
- Official overview: https://www.asd-ste100.org/about_STE.html

ASD-STE100 is copyrighted by ASD. Do not copy its controlled dictionary into Witch Dog.
