# Contributing to Provared

Thank you for reading this far. Provared is one person's work, in their
own time, and help is welcome in these forms.

**Fault reports and suggestions.** Open an issue at
https://github.com/provared/provared/issues, or write to hello@prova.red.
Say what you did, what you expected and what happened; a record that
shows the fault is the best report. A fault in the security of a record
goes by email first: see `SECURITY.md`.

**Questions about the format.** The format is described exactly in
`spec/provared-format.md`, and its core is an individual Internet-Draft
at the Internet Engineering Task Force
(https://datatracker.ietf.org/doc/draft-izmaylov-agent-permission-receipts/).
A question about a rule, or a case where two checkers could disagree, is
worth an issue: the shared test files in `test-vectors/` exist so that
any implementation can be held to the same answers, and a new case can
be added to them.

**Another implementation.** Anyone may implement the format: the
description and the documents are under the Creative Commons Attribution
4.0 licence, and the shared test files say what a checker must answer.
An implementation that passes them is welcome to say so, and to be
linked from the README.

**Code.** Changes to the code in this repository are accepted only under
a contributor agreement, so that the ownership of every line stays
clear. The agreement's text is not ready yet. If you want to contribute
code, open an issue describing the change first, or write to
hello@prova.red, and the author will send the agreement when it exists.
Until then a change sent as a pull request is read, and may be rewritten
by the author in their own words rather than merged.

**What to expect.** The author answers within a few days. Tests are
written with `node:test` and Python's `unittest`, with no test framework;
the library has no runtime dependencies in JavaScript and one (the
package `cryptography`) in Python, and that does not change. Every
change is listed in `CHANGELOG.md`. The style is plain English: short
sentences, no jargon, and "evidence, not a verdict" on every document.
