# Mixed-file execution warning

Do not execute a pasted collection as one script when it contains more than one language or document type.

A mixed collection may contain:

- PowerShell code,
- CMD commands,
- JSON configuration,
- Python,
- JavaScript,
- copied website text,
- hashes and notes.

These parts must be separated before use:

```text
*.ps1   PowerShell code only
*.cmd   command wrapper only
*.json  valid JSON only
*.py    Python code only
*.js    JavaScript code only
*.md    documentation only
```

## Required checks

1. Save the original paste unchanged as evidence or reference material.
2. Extract each language into its own file.
3. Remove prose, loose commands and JSON blocks from executable files.
4. Parse or lint each file before execution.
5. Review write operations and scope.
6. Run only on an explicitly authorized system.
7. Prefer audit or preview mode first.

A hash proves that a local file matches a reference value. It does not prove that the content is safe, correctly scoped or appropriate to execute.
