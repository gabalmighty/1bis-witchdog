# Feed the Witch Dog

Help Witch Dog find new threats. Help it test systems with more care.

You can add intelligence feeds, security checks, tests, documents, and verified fixes.

## Contribute intelligence

1. Open a GitHub issue or pull request.
2. Give the official source URL.
3. Name the vendor, product, and affected versions.
4. Add the publication date and update date, if available.
5. Describe the risk and conditions that make it relevant.
6. Give a public reference for each claim.
7. Add a safe test case for the parser or matcher.

Use official vendor and government sources when possible.

Keep feed text as untrusted data. Do not add scripts that execute feed content.

The approved feeds and normalization code are in the tools folder.

## Contribute code

1. Create a branch from main.
2. Keep the first change small.
3. Add deterministic tests and negative test cases.
4. Use least privilege and bounded input.
5. Keep missing evidence as UNKNOWN.
6. Open a pull request.
7. Attach test results and describe known limits.

Do not add an automatic production fix or an unreviewed privileged command.

Do not change the model's permissions based on a web page, log, or repository comment.

## Contribute detection rules

Include one positive test and one negative test.

Explain the source indicator and its expected behavior.

A rule match is a lead. It is not proof of compromise.

## Protect client data

Do not commit credentials, private keys, employee records, internal URLs, or incident logs.

Do not post exploit payloads from an active client engagement.

Use [private vulnerability reporting](SECURITY.md) for security defects in Witch Dog.

## Run the checks

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q tools
python3 tools/check_docs_style.py --advisory README.md docs/*.md
```

On Windows, use `py -3` for the Python commands.

## Write clear documents

Follow [the Witch Dog writing rules](docs/writing-standard.md).

Use short sentences. Give one instruction at a time.

Name each test, result, source, and limit.

Do not copy code from a project with an incompatible license.

Witch Dog uses the [MIT license](LICENSE).
