# Reporting a fault in the security of Provared

Provared is a format for signed records and a checker that reads them.
A fault that lets a changed record read as intact, lets a record read as
within its permission when it is not, lets a signature or a time-stamp
be forged, or lets the stub writer take an action after the person's
cancellation reached it, is a security fault.

**Write to hello@prova.red** with the subject "Security", saying what
the fault is and how to show it (a record, a command, a few lines of
code). The author reads every message and answers within a few days.
Please do not open a public issue for such a fault until it is fixed,
so that records already made are not put at risk; every other fault and
suggestion is welcome as an issue at
https://github.com/provared/provared/issues.

What happens next: the author confirms the fault, fixes it, adds a test
that fails on the old code, publishes a new version on npm and the
Python Package Index, and says in `CHANGELOG.md` what was wrong, with
credit to whoever reported it unless they ask otherwise. There is no
money for reports: this is one person's unpaid work.

Which versions are looked after: the latest published version. Every
published version stays on npm and the Python Package Index, so that a
record made with one version can always be checked by that version;
but faults are fixed only in the latest.

What the record does not protect against is set out, before any report
is needed, in `docs/threat-model.md`. An agent that acts and writes no
stub leaves no trace, and a one-sided stub is one side's word: those
are stated limits of the format, not faults.
