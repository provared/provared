# AMW's published test data

The four JSON files in this folder (`keys.json`, `permits.json`,
`receipts.json`, `rotation.json`) are copied unchanged from the folder
`spec/test-vectors/` of the repository
https://github.com/agentmiddleware/agent-middleware at commit
`326341c`, the project Agent Middleware (AMW). That repository's
`LICENSING.md` places them under the Apache License 2.0 (only its
`gateway/` folder is under another licence, and nothing from it is
here). Copyright in them belongs to the Agent Middleware authors; the
Apache License 2.0 is in `../../LICENSE`.

They are test data only: the keys are AMW's fixed test seed, as its own
`README.md` says ("Test use only"). They are read as data by the tests
beside them, and nothing else from that repository (no script, verifier
or program) was read, copied or run.
