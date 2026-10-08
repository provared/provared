# Changelog

## 0.2.0 (8 October 2026)

- 2026-10-08: version 0.2.0, for the npm package and, for the first
  time, the Python package `provared` on the Python Package Index. Both
  give the same answers, as the shared test files in `test-vectors/`
  show. The version rises from 0.1.0 because the format's rules changed:
  the exact rule for a page address in a slip, weak Ed25519 keys and
  signatures refused, and strict keys in a time-stamp service's
  certificate. Version 0.1.0 accepts a forged time-stamp where the
  person checking names as trusted a service whose certificate has an RSA
  public number of 1; 0.2.0 refuses it. The entries below say what
  changed.
- 2026-10-08: fixes from an independent review of `record_function`, the
  examples and the wording for a proposed action. None made a book read
  as intact, or within its slip, when it was not.
  - Python: a whole number in a tool's arguments that JavaScript cannot
    hold exactly (beyond 2^53 - 1, unless a float holds it exactly) is
    refused. Before, `2**60 + 1` and `2**60` left the same fingerprint in
    their stubs, though the tool was handed the exact number. JSON is now
    read as JavaScript reads it here too: a whole number beyond 2^53 - 1
    is the nearest float.
  - Python: a number of a class built on int or float (an Enum of whole
    numbers, say) is written as its value, so its fingerprint is that of
    the same arguments kept as JSON. Before, it was written as its name,
    which is not JSON.
  - A generator function is refused as a tool (`recordTools` and
    `record_tools`) and by `record_function`: calling one does not run
    its body, so its stub was written for an action not yet taken.
  - Python: a dict in a tool's arguments whose names are not all text is
    refused. Before, `{101: 2, "101": 5}` reached the tool as `{"101": 5}`.
  - Python: `record_function` refuses, when it is handed the function, a
    parameter whose type can never be plain data (a class of its own,
    such as a model or a date, a tuple or a set), an object whose
    `__call__` is defined with `async def`, and a function whose name is
    not text, each in words of its own. A call whose arguments are not
    plain data names the argument.
  - Python: the README and the docstring say that the function is run
    with a copy of its arguments, and what the record leaves out (an
    argument bound into a `functools.partial` in place).
  - The check before acting says "the action gives no amount", not "the
    stub gives no amount". The shared file `check-before.json` now holds
    a case for each of the words for a proposed action.
  - Examples: `offline()` also refuses the other kinds of name look-up,
    messages sent without a connection, starting another program, a
    connection made by Python's event loop on Windows (which raises no
    audit event), and a connection to a port on this computer that the
    same program does not hold, such as a proxy's. The tests check that
    nothing was refused while each example ran. Its README says exactly
    what it refuses.
- 2026-10-08: examples for three widely used Python agent frameworks, in
  `python/examples/`, the one folder that names them. Each records an
  agent's tools with `record_function`, runs the agent with the
  framework's own stand-in model (no AI service is called; tracing is
  switched off; any connection outside the program is refused while it
  runs), and checks the book. Each is tested
  (`python/examples/test_examples.py`). The library itself still names no
  product.
- 2026-10-08: the check before acting speaks of an action that is only
  proposed: "With this action the total would be 280 GBP", not "With this
  stub the total is", since no stub exists for an action that is not
  taken. Likewise for a count and a period. The codes are unchanged; the
  checker's words for a stub are unchanged.
- 2026-10-08: the Python version gains `record_function`, which puts one
  ordinary function behind the stub writer and keeps its name, its
  parameters and its description, so that an agent framework describes
  the recorded function to its model as it would the function. Python
  only: a JavaScript tool takes its arguments as one object. Tested
  (`python/tests/test_record_function.py`).
- 2026-10-08: `test-vectors/README.md` says what each shared file holds
  and what must match: Provared's own libraries give every answer
  exactly, words included; another implementation needs to match the
  codes and the shape of each answer. The Python package is made ready
  for the Python Package Index (version 0.1.0, both licence files); it is
  not yet published there.
- 2026-10-08: faults found by a second independent review, of the
  Python stub writer and of the changes above. In 1,183 random
  scenarios (about 79,500 steps) played in both languages, and 140 runs
  with several threads at once, no action was taken after the person's
  cancellation was handed over, and the writer's view of its book always
  equalled a whole check. Each fault is fixed and each is now a test
  (`python/tests/test_review2.py`).
  - **An Ed25519 signature whose first half (R) is a point of small
    order is refused**, in both languages, whatever the key. The holder
    of an honest key could make one for any message; Node.js refused it
    and the OpenSSL beneath the Python version accepted it, so one
    record had two answers (format description, section 3.8).
  - A copy of what the stub writer is handed is refused if it nests more
    than 64 levels deep, in both languages. Before, the JavaScript
    library's limit depended on how much of the stack was in use. The
    depth is measured on the copy, so the caller's value is still read
    once.
  - Python: a cancellation handed to `add` beside a member whose name is
    a number, None or something stranger, or in a read-only mapping, is
    read, and stops the writer, as in JavaScript. An error from the other
    side that is not an `Exception` (such as `SystemExit`) leaves a
    one-sided stub, as any other failure does. `snapshot()` hands back
    the book and the cancellations the writer holds, read together, so
    that another thread's call cannot fall between the two. A number too
    large for a float is no time; options holding objects that cannot be
    copied are kept as they are, as the JavaScript library keeps them;
    the record writers take a datetime with a time zone, as the
    JavaScript ones take a Date.
- 2026-10-08: faults found by an independent review of the Python
  version, which also changed the JavaScript library.
  - **Weak Ed25519 keys are refused.** Under one of the eight Ed25519
    keys of small order, anyone can make a signature that checks.
    Node.js refused such signatures; the OpenSSL beneath the Python
    version accepted them, so with such a key trusted, a slip made by
    someone holding no private key read as sound there. RFC 8032 does
    not say to refuse these keys and libraries differ, so now the
    checker refuses them itself, with any key written in more than one
    way (y not below p): `bad-key` for a key in a record,
    `stamp-invalid` for a time-stamp service's key.
  - **The page address in a slip follows an exact rule.** The checker
    used the URL Standard's own reader of addresses, which for a name
    beginning `xn--` rests on tables of Unicode that differ from one
    version of Node.js to the next, so two checkers could disagree. Now
    `issuer.origin` must be written as a browser writes it, by a rule
    that needs no such tables: `https://` (or `http://localhost`), a
    host of lower-case letters, digits and hyphens in labels, a port
    only where it is not the scheme's own, and nothing more (format
    description, section 4.1). Some addresses the URL Standard allows
    are now refused: underscores and other signs in a host, port 0,
    addresses of numbers.
  - A time-stamp service's key of another kind, or on another curve, is
    refused in words that say so, not as a signature that "does not
    fit".
  - A time is read only from a number of milliseconds or a Date. Text,
    true or a list were read by rules that differ from one device to
    another (text with no time zone was taken as local time).
  - `withoutMethods` that is not a list is set aside when a slip is
    checked, as everywhere else. Before, it made the slip's check fail.
- 2026-10-08: the Python version gains the stub writer beside an agent
  (`open_recorder`) and the connector for an agent's tools
  (`record_tools`, `arguments_fingerprint`, `NotTaken`). So it now does
  everything the JavaScript library does.
  - They are ported one to one and give the same answers: two new
    shared files, `test-vectors/recorder-scenarios.json` (32 scenarios,
    about 1,000 steps) and `test-vectors/tool-scenarios.json` (8
    scenarios), each a world of records made beforehand and a list of
    steps (actions, records, cancellations in every form the writer
    takes, time-stamps, acknowledgements, a clock that fails, writers
    opened again, tools called), with the transcript of what happened.
    The two libraries play each scenario (`test/helpers/scenarios.mjs`
    and `python/tests/scenarios.py`) and must write the same transcript,
    down to the words of every message and how many times the clock was
    read.
  - In Python every call is an ordinary function. The writer's calls
    wait for one another across threads. A call to the writer from
    inside an action it is taking, or from the other side while it
    countersigns, is refused at once, as in Node.js. The other side is
    asked in a thread of its own and given 30 seconds, as before. A
    function handed over that gives a coroutine is refused.
  - `key_set_from_seeds` and `key_set_seeds`: an agent's keys kept
    between runs as their two 32-byte seeds.
  - The Python reading of base64url and the copy of a check's options
    are faster; they give the same answers (a value shared many times in
    the options is now copied once, as the JavaScript library copies it).
  - `test/helpers/world.mjs` can be given the agent's and the service's
    key sets, so that a scenario can hand the same keys to Python.
- 2026-10-08: two faults in the check of a time-stamp from a service,
  found while writing the Python version.
  - An RSA key with the public number 1 in a service's certificate was
    accepted. Under it, anyone can make a signature that checks, so a
    time-stamp could be made without the service's private key. It
    counted only where the person checking had named that certificate as
    trusted. An even public number was accepted too. Now the public
    number must be odd, from 3 to 2^32 - 1 (`stamp-invalid`).
  - The public key inside a certificate was read loosely: a compressed or
    "hybrid" point, RSA numbers with needless or missing sign bytes,
    bytes after the key, any parameters, and unused bits all loaded. Now
    the key must be written exactly as its own standard sets out
    (`stamp-bad-data`), as the rest of a time-stamp already must be, so
    that two checkers cannot disagree about whether it can be read.
  - Each is a shared test (`test-vectors/stamps-strict-keys.json`).
- 2026-10-08: shared test files, and the start of a Python version.
  - `test-vectors/` holds records and values, each with the answer this
    library gives: the canonical form, base64url, times, keys, a
    passkey's signature, the envelope of a record, the content of a stub
    and of a countersignature, page addresses and 170 slips, sound and
    faulty. `tools/make-vectors.mjs` writes them;
    `test/vectors.test.mjs` checks that this library still gives every
    answer. Any other implementation of the format can be tested against
    them.
  - `python/` holds a Python version, built in stages against the same
    files. It is not yet published. It now checks everything the
    JavaScript library checks: slips, stubs, countersignatures, limits,
    approvals, refusals and terms, passes, cancellations and
    acknowledgements, vouching records, seals and their time-stamps,
    block time-stamps, the tree and its proofs, Shows, the chain of
    block headers, and the check before acting. It gives the same answer
    in every one of the 63 shared files, and in 6,091 random books
    compared on this computer. One difference is stated: "cryptography",
    the one package it needs, has no SLH-DSA yet, so a seal's third
    signature is reported as not checked on this device and never as a
    pass. The stub writer and the connector for an agent's tools are
    still to come.
  - A slip whose page address cannot be read, and one whose address is
    not in its plain form, are now refused with the same words. The code
    (`bad-field`) is unchanged.
- 2026-10-07: the README links to the individual Internet-Draft
  `draft-izmaylov-agent-permission-receipts`, which describes the core of
  the format.

## 0.1.0 (6 October 2026)

Draft version 0 of the format, published and not frozen.

- 2026-10-05: `provared-headers` is marked as experimental, in the
  README and in what the command prints.
- 2026-10-05: faults found by an independent review of the chain of
  block headers. It found no way to have a block counted unless real
  work made it: no chain file and no answer from a node did. Each fault
  is fixed and each is now a test (`test/headers.test.mjs`).
  - The second node did not have to show anything: an empty answer
    counted as agreeing, a node behind could agree, and other nodes could
    cut the end of the chain or swap it for a branch with no more work,
    after which the file was written shorter. Now the second node is
    asked for the latest six blocks on a copy of the chain and must hand
    them back itself; it must be on a network apart from every node that
    gave headers, judged by the address reached, not the name given; a
    branch near the end is taken on only if it carries more work; and a
    chain file is never written shorter than it was.
  - A node could keep `provared-headers` waiting for ever with messages
    of its own, and grow its memory with requests to answer. Now a node
    is given fifteen minutes at most, only answers to what was asked keep
    a session open, and answers to its own messages stop while it does
    not read them.
  - The list of threats said that a branch after the last known block
    must carry the real chain's work for every block. The rules on
    difficulty let a branch with dates pushed forward ease its targets at
    each change. Now, after the last known block, no target may be more
    than four times easier than that block's, and the list of threats
    states what a false block then costs, and that a chain file someone
    else hands over is only as good as they are.
  - With `--headers`, the checker said that a block found in the chain
    was one "you named as trusted", and that a block named with
    `--block` was not counted. It now says why each block counts, and
    `--json` gives what the chain showed beside the result.
  - A file that could not be written ended the command with an error of
    its own, and a run that fetched nothing wrote the first block alone.
    Now both are said plainly, nothing is written, and a chain file is
    made sure to be on the disk before it takes the old one's place.
  - Also: the lowest header version after the upgrades of 2013 and 2015,
    and a target of zero, are refused, as nodes refuse them; node
    addresses are read strictly, and lines of a file of nodes that are
    not addresses are counted and said.

- 2026-10-05: a block time-stamp can be checked with no node of your
  own. A new command, `provared-headers`, fetches the chain of Bitcoin
  block headers from nodes the person names, and from no one else, and
  keeps it in a file; a second node on another network must hold the same
  latest block. `provared-check --headers <file>` checks that file on the
  device, from the chain's first block, by the rules every Bitcoin node
  applies to headers, and against ten blocks known to be part of the
  chain; a block time-stamp then counts if its block is in the chain with
  at least six blocks after it. In the library: `checkHeaderChain` and
  `blocksInChain`. The network code sits apart, in `net/`, and only the
  new command uses it: the library and the checker still make no
  request. New code: `headers-invalid`. Tried once against the real
  network: the whole chain, 970,076 headers checked from the first
  block, in about six minutes, the same headers as the test against real
  proofs fetched; a second run fetched only what was new. Built from the
  script of that test.

- 2026-10-05: faults found by a broad final review of the package as it
  is to be published. It found nothing that made a changed record read
  as intact, nothing that crashed the checker, and no request made by
  the checking page built as one file. Each fault is fixed and each is
  now a test (`test/review20.test.mjs`).
  - **Exit code 0, and the checking page's green answer, now need the
    keys you named:** the passkey you trust and, where the record has a
    seal, the recorder you expect. Before, a stranger's record, or a book
    cut short and sealed again with other recorder keys, gave code 0
    with nothing trusted named. The command-line checker now says
    whether the check rests on keys you named. The library's own answer
    is unchanged.
  - The command-line checker refuses a trust value that is not a
    fingerprint (a typing error had left a time-stamp quietly not
    counted), refuses an option given twice where it may be given once,
    ends with code 0 for `--help`, and does not repeat Node.js's warning
    that its ML-DSA and SLH-DSA are experimental.
  - A run of more than three marks drawn on one letter (accents, for
    one) is shown as three and one visible mark, on the page and in the
    terminal, and each value on the page stays inside its own box. A
    purpose of one letter and 999 such marks had been drawn over the
    page's answer.
  - Checking the sample on the page no longer leaves the sample's
    fingerprints in the boxes, where they made the next record chosen
    read as signed by a passkey not trusted.
  - A stub whose slip fails is no longer counted as one-sided: its
    countersignature, not checked, is `unchecked`.
  - In a browser, a slip can now be cancelled with its passkey
    (`cancelWithPasskey`), and anything prepared for a passkey, such as
    a slip with covered fields, signed (`signChallengeWithPasskey`).
  - A line that ends with a carriage return before its line feed, a
    byte-order mark, or an empty line is now named as such. The codes
    are unchanged.
  - The README says how to install and import the package, and which
    commands need a copy of the repository. Two of its claims went
    further than the code: the check before acting refuses more than a
    checker reports in one case, and a seal fixes what is before it only
    for a recorder you named. Both now say so. `package.json` names both
    licences and the repository. Out-of-date sentences in the list of
    threats and the format description are corrected, and a time-stamp
    shows that entries "existed by" a time, for both kinds.

- 2026-10-05: faults found by a nineteenth independent review, of the
  eighteenth review's fixes. Each is fixed and each is now a test
  (`test/review19.test.mjs`). In 3,900 random steps the review found
  no action taken after the person's cancellation was handed over, no
  difference between the stub writer's view of its book and a whole
  check, and no line written that made the book fail its check.
  - The entry below for the eighteenth review says that a value too
    large to be a line of a book is refused before it is written out.
    The limit counted values, not their length, and each member of an
    entry by itself. So a long text met many times, or one long list
    named by many members, could make `add` use gigabytes of memory, or
    end the process, before the call waited its turn. The copy is now
    measured by the length its text would have: each of the three
    members of a cancellation has room for a line, and the other
    members share one line's room. Past that, the entry is not written
    as it was handed over, and the cancellation in it still stops the
    writer. Anything but an object, such as a list, is no longer written
    out, and one that cannot even be looked into is refused through the
    answer, not thrown.
  - A list whose length is not a whole number (a Proxy can say
    anything) was copied as a list that held that value. A list of
    trusted passkeys whose length was a passkey's thumbprint then
    trusted that passkey, and in `add` a list of time-stamps whose
    length was a time-stamp put it into the book. In the options such a
    list is now kept as it was handed over; in `add` it is not plain
    data.
  - An option for the signing methods to treat as not built in that
    could not be read made a whole check and a carried checker throw.
    It is now a problem with the whole check (`check-failed`).
  - A value more than 16 levels down in the options was kept as it was
    handed over. Through a value met twice it could appear near the top
    of a carried checker's options, so that a change made afterwards
    changed its answer. Nothing past that depth is kept now: it cannot
    be read.
  - The stub writer copied the passkeys it trusts with the platform's
    own copy, which refuses a list wrapped in a Proxy. They are now read
    through the same fixed copy as the other options.
  - The check before acting no longer copies its options twice, and a
    gap at the end of a list in the options is now held by a test.

- 2026-10-05: the block time-stamp checked once against real proofs.
  Two complete proofs that others had published, one made by hand and
  one made by public calendar services, were read with this library's
  reader against the headers of the real blocks they name: each led to
  its blocks (five in all), and each was refused with another block's
  header or with its file changed by one bit. The headers came from the
  whole chain of headers, checked from its first block. The proofs and
  their files are not copied into the repository, and the tests still
  use made-up blocks. The README and the list of threats say so.

- 2026-10-05: faults found by an eighteenth independent review, of the
  seventeenth review's fixes. Each is fixed and each is now a test
  (`test/review18.test.mjs`). In 18,000 random steps the review found
  no action taken after the person's cancellation was handed over, no
  difference between the stub writer's view of its book and a whole
  check, and no line written that made the book fail its check.
  - Since the seventeenth review's fixes, a whole check, a Show and the
    check before acting read their options through a fixed copy. Options
    that shared values many times over, or that held themselves, then
    took more than twenty seconds to copy, or used up the memory. A
    value met twice is now copied once, so the copy costs no more than
    the options hold.
  - An option that cannot even be looked into (a revoked Proxy) made a
    whole check, a carried checker and the stub writer throw an error of
    the platform's own, where they should answer. It is now a problem
    with the whole check (`check-failed`), and the stub writer refuses it
    when it is opened (`bad-field`).
  - What is handed to `add` was copied in two steps where it could not
    be copied at once (a Proxy beside it), so a member could be read
    twice, and a member that changed between the two readings could let
    the writer act after the person's cancellation was handed over. It
    is now copied in one pass, each member and each place read once. In
    the same way, a sound time-stamp beside a gap or a faulty item, in a
    list wrapped in a Proxy, is no longer lost. A value too large to be a
    line of a book is refused before it is written out.
  - An acknowledgement that waits, carried by a copy given at opening,
    was the first to give way where more than sixteen were held. The
    acknowledgements that wait now give way newest first.
  - A copy of a cancellation given at opening that could not be copied
    as plain data was kept as the caller's own object, and a later `add`
    could then fail on it. It is now refused when the writer is opened.
  - The check before acting read the passkeys it trusts once for the
    book and again for its decision. It now reads its options once.
  - Three fixes of the seventeenth review are now held by tests. The
    list of threats said that an entry which does not fit made the
    stub writer read its book again from the start; it costs one line's
    check, and the list now says so.

- 2026-10-04: faults found by a seventeenth independent review, of the
  sixteenth review's fixes. Each is fixed and each is now a test
  (`test/review17.test.mjs`). In 25,800 random steps the review found
  no action taken after the person's cancellation was handed over, no
  difference between the stub writer's view of its book and a whole
  check, and no line written that made the book fail its check.
  - A sound cancellation handed to `add` wrapped in a Proxy (as some
    user-interface libraries wrap objects) could not be copied, was taken
    as unreadable, and did not stop the writer. This came from the
    sixteenth review's fixes. What cannot be copied as it stands is now
    copied through its canonical text, still read once.
  - An acknowledgement that waits, carried by a copy given at opening,
    was counted neither in the room the writer keeps nor among the
    waiting ones, and could be cut off. It now counts with the waiting
    ones.
  - With the clock failing, an acknowledgement of the agent's own handed
    over with a cancellation the book holds was taken but neither
    written nor handed back. It now waits, and is handed back and
    written as one that could not be written at once.
  - Opening the stub writer with a very long, nearly empty list of
    cancellations took time in proportion to its length. It no longer
    does.
  - A whole check and a carried checker could still read some unusual
    lists in the options differently (a list with its own way of
    walking through itself, or its own `includes`, or of a class). A
    whole check now reads its options through the same fixed copy, and
    a copy's acknowledgements and a slip's disclosures are read place by
    place.
  - A Show said that cancellations were handed over beside it where the
    list was empty. An empty list is now none, as for a whole book.
  - Tests now hold in place the room kept for the writer's own
    cancellations given at opening, and the limit of 100,000 trusted
    blocks.

- 2026-10-04: preparing the first publication. The package version is
  0.1.0. The package holds the library, the command-line checker, the
  format description, the list of threats, the sample record, the
  checking page, the licences, the README and this change log; the
  tests and the demonstration stay in the repository. The README now
  says, as the list of threats did, that no complete block time-stamp
  from a real service has been checked yet.

- 2026-10-04: faults found by a sixteenth independent review, of the
  fifteenth review's fixes. Each is fixed and each is now a test
  (`test/review16.test.mjs`). In 9,600 random steps the review found no
  action taken after the person's cancellation was handed over (but for
  the case below of a member whose value changes), no line written that
  made the book fail its check, and no difference between the stub
  writer's view of its book and a whole check.
  - An acknowledgement that waits to follow its cancellation into the
    book could be cut off by cancellations kept after it, and copies of
    other slips' cancellations given at opening could crowd out the
    writer's own. The writer now holds its own slip's cancellations
    first, then the acknowledgements that wait, then the other copies,
    which give way.
  - `add` read what it was handed more than once: a member whose value
    changed from one reading to the next could leave the writer
    unstopped. It is now read once, member by member.
  - An option, or a place in a list, that cannot be read made a carried
    checker and the stub writer crash where a whole check answers. It
    now fails exactly where a whole check reads it; the stub writer
    refuses such options when it is opened.
  - The list of blocks and a copy's time-stamps were read through a
    list's own way of walking through itself; they are now read place
    by place. A very long list with no items in it made a carried
    checker hang; only the places that hold an item are now copied, and
    the list of blocks holds at most 100,000.
  - A copy of a cancellation given at opening as an object of a class
    was changed by the writer, and one that was frozen made every `add`
    fail. Such a copy is now copied as plain data.
  - A writer opened from a book with two acknowledgements of its own
    agent handed back the second; a copy given at opening could end up
    with two. The first is taken, and a copy takes no second one.
  - The empty list that a writer holding no cancellation hands back was
    refused when it was handed in again. An empty list of cancellations
    is now accepted as none.
  - Of the time-stamps the writer counts on a cancellation it holds, the
    earliest are now kept.
  - The documents now say that a writer keeps every cancellation of its
    slip, and that where the clock fails the error is the clock's own.

- 2026-10-04: the checking page tried again in current browsers: three
  test builds and two installed desktop browsers at version 154, with
  and without experimental features. None has ML-DSA or SLH-DSA built
  in; each says plainly that the check is not complete, and none shows
  a pass. No horizontal scrolling at phone width. The page built as one
  file refused every request made from inside it. One fault, fixed: in
  the page built as one file, a record chosen before the page's script
  had started was ignored without a word (seen in one browser build). A
  record already chosen when the script starts is now checked.

- 2026-10-04: faults found by a fifteenth independent review, of the
  fourteenth review's fixes. Each is fixed and each is now a test
  (`test/review15.test.mjs`). In 2,500 random calls the review found no
  action taken after the person's cancellation was handed over, no line
  written that made the book fail its check, and no difference between
  the stub writer's view of its book and a whole check.
  - A list with a gap in it, beside a cancellation, was written as text
    that is not JSON. With the clock failing, the cancellation was then
    lost: a writer opened again took actions. A list with a gap is now
    refused as not JSON (`payload-not-canonical`), and the sound
    time-stamps in such a list are still kept.
  - A time-stamp from a service the writer was not told to trust, kept
    with a cancellation, kept out a trusted one handed over later; so
    did a trusted one that was late. The writer now merges the
    time-stamps it holds with those handed over: each is judged by
    itself, the ones it counts come first, four at most. Of a list with
    a faulty time-stamp in it, the sound ones are kept.
  - With the clock failing, the acknowledgements handed over with a
    cancellation were dropped, and a writer signed a second one later. A
    copy could hold two acknowledgements of the writer's own agent, and
    a writer opened again took the last of them where `add` took the
    first. They are now kept on a clock failure; only the first of the
    agent's own is taken, everywhere; the agent's own is found among more
    than four.
  - A copy of a cancellation given at opening with a member that is not
    enumerable was checked with it and handed back without it. Such a
    copy is now made plain data before it is checked.
  - The copy of the options read a member that a whole check never
    reads, and turned a gap in a list into an empty place. A member that
    cannot be read is now kept as it is, and a gap stays a gap; a gap in
    the list of blocks, or of a copy's time-stamps, is refused.
  - Where a kept cancellation was written into the book in the same
    call, the error said it was not added. It now says what was done.
  - An acknowledgement still waiting to follow its cancellation into the
    book was not handed back, and was lost to a writer opened again. It
    is now handed back with the cancellation, and written by a writer
    opened again.
  - With the clock failing, the error for a cancellation that cannot be
    kept, because the writer already holds 16, now says so.
  - Tests now hold in place nine fixes of the fourteenth review that
    could be undone without any test failing. Each fix of this review,
    and each of those nine, was then undone in turn in a copy of the
    code: a test caught every one.

- 2026-10-04: faults found by a fourteenth independent review, of the
  thirteenth review's fixes. Each is fixed and each is now a test
  (`test/review14.test.mjs`). In 3,000 random calls the review found no
  action taken after the person's cancellation was handed over, no line
  written that made the book fail its check, and no difference between
  the stub writer's view of its book and a whole check.
  - `add`, handed a cancellation with several acknowledgements, could
    take one that does not check (signed with other keys, or given for
    another cancellation) as its own agent's, hand it back, and keep it
    with the cancellation, so that nothing more could be added to the
    book. Each acknowledgement is now checked by itself, and only one
    that checks is taken.
  - A sound time-stamp on a cancellation was lost where the clock
    failed, and where it was handed over only after the date of a kept
    cancellation had come. The writer now keeps the cancellation with
    its sound time-stamps, and takes a time-stamp into a kept
    cancellation before it writes anything into the book.
  - Where a copy already held four acknowledgements of helper agents,
    the writer's own was handed back and not kept, and a writer opened
    again signed a second one. The writer's own is now always kept; the
    last of the others gives way. Sound acknowledgements of other agents
    that come with a cancellation stay with the kept copy.
  - A member that is not enumerable, one level down in the options, was
    made enumerable by a carried checker, which then refused what a
    whole check does not see. It now stays as it was.
  - A tool's function that kept the object it gave as `amount`, or the
    list it gave as `details`, could change it before the second try,
    after the person's approval. What these functions give is now
    copied. Each member of a tool's description is read once.
  - The error for a cancellation that cannot be kept, because the writer
    already holds 16, now says so.

- 2026-10-04: faults found by a thirteenth independent review, of the
  eleventh and twelfth reviews' fixes. Each is fixed, or stated, and
  each is now a test (`test/review13.test.mjs`). The review found no way
  to make a whole book or a Show read as intact, or as within its slip,
  when it is not, and no way to make the stub writer's view of its book
  differ from a whole check.
  - The stub writer could date its acknowledgement before a pass that
    its agent had handed on (a pass may be dated up to 300 seconds
    ahead of the clock), so that an honest pass, and the stubs under
    it, read as made after the agent was told. It no longer does.
  - A tool's own function could change what the tool was recorded as,
    through `this`. Each function is now called by itself, and the
    description is frozen.
  - A cancellation given when the writer was opened was handed back
    without the acknowledgement signed for it, and did not take a
    time-stamp handed over later. It now does both, and stops the
    writer from the start.
  - `add`, handed the form that `cancellations()` gives back, dropped a
    sound time-stamp. It now adds the cancellation with its
    time-stamps, and goes on handing back an acknowledgement of its own
    agent that came with it.
  - A clock that failed while the person's cancellation was handed over
    lost the cancellation, and the writer acted on. The writer is now
    stopped, and keeps the cancellation, before the clock is read.
  - A clock that gave no time (`NaN`) switched off the rule that
    nothing is written dated ahead of the clock. It now counts as a
    clock that failed.
  - An acknowledgement dated ahead of the clock was never written into
    the book. It is now tried again.
  - The words a stub was given depended on the order of the
    acknowledgements in one copy. They no longer do.
  - A member of the options that is not enumerable was dropped by a
    carried checker and read by a whole check. Both now read it.
  - `argumentsFingerprint` threw at once for arguments that are not
    JSON; it now refuses through its promise. Stated: `0` and `-0`
    share a fingerprint, as RFC 8785 sets out.

- 2026-10-04: the author is named in the format description's copyright
  line, in the README and in `package.json`.

- 2026-10-04: faults found by a twelfth independent review, of the
  acknowledgement and of the connector for an agent's tools. Each is
  fixed and each is now a test (`test/review12.test.mjs`). The review
  found no way to have an acknowledgement counted that the agent's side
  did not sign, to have a stub excused through one, or to run a tool
  that the slip does not allow.
  - The stub writer could date its acknowledgement before its own last
    stub (a stub may be dated up to 300 seconds ahead of the clock), so
    that an honest stub read as made after the agent was told. It no
    longer does.
  - Different arguments could share one fingerprint: a list with a gap
    in it, or with a named member, was written as if it had neither. It
    is now refused as not JSON, and the tool is not run.
  - What a tool is was copied one level deep, and one object went to
    all of a tool's functions and then to the tool. Each now gets a copy
    of its own, and a tool's description is fixed through and through.
  - The person was asked to approve an action that could not be taken
    anyway (the slip also asks for a countersignature, and the tool has
    no way to ask for one). They are no longer asked, and the stub
    writer's answer names both things that are missing.
  - An acknowledgement in a book still passed after the cancellation it
    names had failed its check further on in the book. It no longer
    does (`cancellation-not-found`).
  - Which words a stub was given depended on the order in which copies
    were handed over. The time-stamp rule is now applied first, for
    every copy; a stub it reports keeps that finding, and is told in
    addition where it is also dated after the acknowledgement.
  - An acknowledgement was given as confirmed where the device could
    not confirm the slip or the copy. It is now given as not checked.
    The command-line checker no longer shows what such a copy says.
  - Changed after the reviewer's design remarks: a pass handed on after
    the agent's side acknowledged, every pass handed on from it, and
    every stub under them, are reported; an acknowledgement that does
    not check is still a problem with the whole check, but the person's
    copy of the cancellation is used all the same; a stub writer opened
    with keys that are not the agent's hands back no acknowledgement.
  - The type declarations said that `cancellations()` hands back
    cancellations with their time-stamps only. They now say that each
    comes with the acknowledgement the writer signed.

- 2026-10-04: faults found by an eleventh independent review, of the
  checker that can be carried on, of the stub writer that carries its
  book on, and of the tenth review's fixes. Each is fixed, or stated as
  a limit, and each is now a test (`test/review11.test.mjs`). In 240
  random books the reviewer's carried checker never differed from a
  whole check, and in 2,483 random calls the stub writer never differed
  from a whole check of its book.
  - A clock that failed part of the way through `add` left the stub
    writer's reader holding a line that its book did not. Every line is
    now tried on a reader split off the book's own, which takes the
    book's place only if the line is written. An entry that does not
    fit now costs one line's check, where it cost a reading of the
    whole book.
  - Options that were inherited, worked out when asked for, or objects
    of a class were dropped or changed when a carried checker or the
    stub writer copied them, so that the answer could differ from a
    whole check's. They are now read once, as a whole check reads them.
  - A new rule: a seal dated more than 300 seconds before a time-stamp
    that it covers (a service's time-stamp on a seal before it) is
    reported (`time-went-backwards`). Stated beside it: what a Show
    cannot show where the earlier seal is left out of its pages.
  - A cancellation given when the stub writer is opened is now written
    into the book once its date has come; every cancellation of its
    slip that the writer is handed is kept, not only the first; one
    kept without a time-stamp takes the time-stamp it is handed over
    with later; and `cancellations()` hands each back with the
    acknowledgement the writer signed, so that a writer opened again
    hands back the same one.

- 2026-10-04: the checking page as one file. `node
  tools/make-single-page.mjs` writes `provared-check.html`: the page, its
  style, the checker and the sample record in one file, copied in
  unchanged, which opens in a browser from the disk with no server. Its
  content security policy allows no request of any kind. Tests:
  `test/single-page.test.mjs`. Tried in three browser builds.

- 2026-10-04: a connector between an agent's tools and the stub writer.
  `recordTools(recorder, tools)` puts each tool behind the stub writer:
  a call asks first, runs the tool only if the slip allows the action,
  and writes the stub. A call that is not allowed throws `NotTaken`.
  Where the slip asks for the person's approval, the tool's `approve`
  function is asked for it once. By default the stub names one
  document, `arguments`: the fingerprint of the call's arguments,
  written in the one form of RFC 8785 (`argumentsFingerprint`). It
  names no agent software. Tests: `test/tools.test.mjs`.

- 2026-10-04: the acknowledgement, a new kind of record (format
  description, section 26). The agent's side states, with the agent's
  own keys, that it was handed the person's cancellation of a slip, and
  when. A cancellation shows when the person signed it; until now
  nothing showed that the agent's side was told.
  - The record: `provared.acknowledgement.v0`, with the label
    `vnd.provared.acknowledgement.v0+json`, signed with the two keys of
    the slip's agent, or of a helper agent under its pass.
    `writeAcknowledgement` writes one.
  - In a book it is an entry of its own, `{"acknowledgement": ...}`,
    after the cancellation it names. A new code:
    `cancellation-not-found`.
  - The person hands it to a checker with their own copy of the
    cancellation (`acknowledgements`, up to four). Every stub of that
    agent dated after the acknowledgement is then reported, in words of
    its own, even where the copy has no time-stamp. Where the book
    leaves the cancellation out, the checker says that the agent's side
    had acknowledged it. A new code: `acknowledgement-mismatch`.
  - The stub writer signs an acknowledgement whenever the person's
    cancellation of its slip is handed to `add`, writes it into the book
    after the cancellation, and hands it back: in the answer of `add`,
    or in the `acknowledgement` member of the error where `add` fails.
  - The checker's answer: a new kind of entry, `acknowledgement`; a new
    count, `summary.counts.acknowledgements`; and `acknowledgements` on
    each cancellation handed over beside the book. The command-line
    checker and the checking page show them.
  - Tests: `test/acknowledgement.test.mjs`, and the two new codes in
    `test/refusals.test.mjs`.

- 2026-10-04: a checker that can be carried on. No record and no rule of
  the format changes: only how fast the free library works.
  - `openChecker(book, options)` reads a book once and then takes more
    lines (`add`), without reading the earlier ones again. Its answer
    (`result`) is the answer `checkBook` gives for the same text. A
    whole check is now: start, read every line, give the answer; there
    is one way of reading a line.
  - The stub writer carries its book on. One action no longer checks
    every signature in the book twice. Measured on one computer, with
    countersigned stubs: 9, 14 and 23 thousandths of a second for one
    action after 400, 1,600 and 6,400 stubs, where it took 2.0 seconds
    after 400 and 7.7 after 1,600.
  - `recorder.check()` gives the checker's answer for the writer's book
    as it stands. `recorder.before()` now waits its turn with the other
    calls.
  - What can be found only once every stub has been read (a limit "in
    any period", what a cancellation handed over beside the book shows)
    is worked out afresh for each answer, and is no longer written into
    what the checker keeps while it reads.
  - New tests (`test/carried.test.mjs`): the carried checker against a
    whole check after every line of a book with every kind of entry;
    trying a stub leaves the book's reader as it was; the stub writer's
    view of its book against a whole check after every call.

- 2026-10-04: faults found by a tenth independent review, of the ninth
  review's fixes. Each is fixed, or stated as a limit, and each is now a
  test (`test/review10.test.mjs`). With time-stamps that tell the truth,
  the review found no way to make a whole book or a Show read as intact,
  or as within its slip, when it is not, apart from the two narrow cases
  below (the seal of a Show, and a rare kind of block).
  - The stub writer lost a cancellation that the person had signed when
    something beside it could not be written as a line of a book
    (`stamps: undefined`, for example), and went on taking actions.
    `add` now adds the cancellation by itself where what stands beside
    it is at fault, and the call still fails and says what was done.
  - A cancellation that the stub writer kept, because it was dated ahead
    of the clock, was never written into the book, and a writer opened
    again from the book took actions again. The writer now writes it
    into the book once its clock has reached that date, whole, with the
    person's time-stamps. Until then `cancellations()` hands back what
    the writer holds, to be kept with the book. Stated as a limit: a
    writer opened from the book alone knows nothing of it.
  - A cancellation with no counted time-stamp of its own was shown as
    "counts as cancelled at" the time of a later seal. The checker's
    answer now keeps two times apart: `existedBy`, the time by which a
    later seal shows that an entry existed, and `stampedAt`, the time
    that a seal's or a cancellation's own time-stamps give it. **This
    changes the answer's shape:** for a slip, a stub and the other kinds
    of entry, what was `stampedAt` is now `existedBy`.
  - The seal that comes with a Show was not held to the rule that no
    unique number appears twice. It now is, against the pages.
  - A block time-stamp beside a later seal that stated a time before a
    service's time-stamp on an earlier seal was credited, and could
    excuse a stub made after a cancellation. It is now set aside, and
    the checker says so. It needs a block that states a time far behind
    the true time.
  - A seal or a cancellation that did not pass its check no longer shows
    a time of its own.
  - A date was reported against the time-stamp of a cancellation whose
    passkey signature the device could not check. It no longer is, as
    for a seal.
  - The format description and the list of threats said that a page
    dated after a seal's time-stamp is the page reported in a Show. The
    seal is.

- 2026-10-03: faults found by a ninth independent review, of the eighth
  review's fixes. Each is fixed, or stated as a limit, and each is now a
  test (`test/review9.test.mjs`). The review found no way to make a
  whole book read as intact, or as within its slip, when it is not.
  - A cancellation dated ahead, put into a block at once and
    time-stamped by a service on its date, counted from the block's
    time: days before the date the person signed. Honest stubs were then
    reported. A cancellation is now never taken to have been made before
    its own date, and the checker says that the two time-stamps do not
    agree.
  - A seal with an early block time-stamp and a later one from a service
    counted from the later. Every counted time-stamp of a seal is now
    taken, and the earliest counts. A block that states a time long
    before the seal's own date, beside a service's time-stamp, is still
    set aside, and the checker says so.
  - In a Show, an old seal that did not belong to the book marked the
    honest page before it. The finding is now given for the seal.
  - In a Show, a seal was not held to the chain of seals. It now is, as
    far as the pages show the chain.
  - The stub writer wrote an approval dated up to 600 seconds ahead of
    its clock. It now writes none dated more than 300 seconds ahead.
  - The stub writer kept at most 16 cancellations that it could not add,
    of any slip in the book, and dropped the next: its own slip's
    cancellation could be the one dropped. It now keeps one, of its own
    slip.
  - Stated as limits in the documents: the time-stamps beside the seal
    of a Show, and beside the last seal of a book, can be swapped for
    later ones (the gain is at most 300 seconds); a person can keep a
    cancellation back and hand it over later; only a late time, not a
    late time-stamp beside a prompt one, is pointed out on a
    cancellation.

- 2026-10-03: the checking page takes what the command-line checker
  takes. A fifth box names the blocks you trust. A second panel takes the
  person's own copies of cancellations (up to 16 files) and one file of
  disclosures for covered fields; each handed-over cancellation is shown
  as a card, saying whether the book holds it. A file that is not JSON
  stops the check. The sample record is checked without those files.
  Tried in three browser builds at phone width.

- 2026-10-03: faults found by an eighth independent review, of the stub
  writer, of which time-stamps give a record its time, and of ten passes
  in a row. Each is fixed and each is now a test
  (`test/review8.test.mjs`). Passing on up to ten times was found sound.
  - A later time-stamp from a service, put beside an earlier block
    time-stamp on a cancellation, moved the cancellation's time later,
    and excused stubs made after the person cancelled; in the person's
    own copy too. Every counted time-stamp beside a cancellation is now
    taken, and the earliest counts.
  - A block time-stamp on a cancellation is no longer taken as earlier
    than the date the person signed in the cancellation. Before, a stub
    that an outside time-stamp showed to have existed before that date
    could still be reported.
  - Where a service's time-stamp and a block time-stamp beside one seal
    do not agree, the checker now says so.
  - A service's time-stamps could step backwards without end, 300 seconds
    at a time. Each is now compared with the latest before it.
  - A Show under a later seal passed where the whole book failed, even
    with the earlier seal among its pages. A seal among the pages is now
    held against the pages and the seals before it. With that seal left
    out of the pages a Show cannot show it, and the documents now say so.
  - The stub writer wrote its line from the caller's own objects after it
    had checked them, so a later change could put a line into the book
    that failed the book's check. What it is handed is now copied when it
    is handed over.
  - `record` handed the stub to the other side before the check of the
    whole book, so the other side could hold two signed stubs for one
    place in the chain. It now checks first.
  - `act` accepted a date in the past, so an action could be taken after
    the slip had ended and dated inside it. A date handed to `act` must
    now be within 300 seconds of the writer's clock.
  - After an other side that never answered, a later call that stemmed
    from that request was refused as "from inside an action". The mark
    now ends when the time to countersign runs out.
  - A countersignature dated up to 598 seconds ahead of the clock was
    written. It is now compared with the clock alone: 300 seconds.
  - The check before acting refuses an action that would add to a period
    which a later-dated stub already overfills, though a checker reports
    nothing new for it. That stays, and the format description now says
    so, where it said the two agree exactly.

- 2026-10-03: a slip may allow up to ten passes in a row (`passes`: 1 to
  10); an eleventh is refused. It was three. Ten is the upper number
  commonly set for chains of delegated access between services, and is a
  first-draft number.
- 2026-10-03: faults found by a seventh independent review, of how
  time-stamps are credited and of the stub writer. Each is fixed and
  each is now a test (`test/review7.test.mjs`). The review found no way
  to make a whole book read as intact, or as within its slip, when it is
  not.
  - A Show under a seal passed where the whole book failed: the seal's
    own date was not compared with the pages. It is now.
  - The stub writer refused a cancellation it could not add (a faulty
    time-stamp beside it, a date ahead of the clock) and went on allowing
    actions. A cancellation the person signed now stops it either way.
  - `act` wrote its line without the whole-book check that `record`
    makes. The stub is now written and checked with the whole book
    before the action is taken; the other side is handed a copy of the
    stub; a stub added through `add` moves the writer's place on.
  - An approval that was not a record let the action be taken and then
    lost its stub. It now stops the action before it is taken.
  - The stub writer accepted its own stub dated ahead of its clock. It
    writes nothing dated ahead of it.
  - A call made after an action had ended could be refused as "from
    inside the action". The mark now holds only while the action runs.
  - A later seal was reported because of an entry that had already
    failed its own check, and one misdated entry excused a seal from
    every other. Each entry is now looked at by itself.
  - A date was reported against a time-stamp that the device could not
    count. It no longer is, and the seal says that the time-stamp was
    not counted.
  - Where a service states the time, its time-stamps now give the time,
    and a block time-stamp beside them is a second witness. A block that
    states a time far behind no longer makes such a seal fail.
  - A time limit of "for ever" for the other side became one
    millisecond; it is now refused. An empty list of documents is the
    same as none in `act` as in `record`.

- 2026-10-03: faults found by a sixth independent review, of the block
  time-stamp and the stub writer. Each is fixed and each is now a test
  (`test/review6.test.mjs`). The review found no way to have a block
  time-stamp counted without a proof that leads to a block the reader
  named, and nothing that crashed or hung the checker.
  - On a cancellation, a block time-stamp's two hours of looseness were
    taken the unsafe way, so a stub made after the cancellation could
    escape. A cancellation now counts from two hours before the time the
    block states, and the time used is shown.
  - A seal dated before an entry it covers was not reported once any
    counted time-stamp existed, even one that settled nothing. It is now.
  - An entry kept the time of the first seal after it, even where a later
    seal showed an earlier time; naming a true block could then turn an
    honest stub into one "after the cancellation". An entry now has the
    earliest time that any seal after it shows.
  - The stub writer accepted a countersignature, or an entry, dated years
    ahead, after which its book could not be sealed. Both are refused.
  - The stub writer could be blocked for good by an other side that never
    answered, or by a call from inside its own action. The other side now
    has a set time; such a call is refused at once (in Node.js).
  - The stub writer relied on an approval's fingerprint as handed over.
    It now works it out from the approval itself.
  - `record` could write a stub that made the book fail its check. It
    now writes nothing unless the book still passes with it.
  - The check before acting ignored the longest line a book may hold. An
    action whose record would not fit is not allowed.
  - `act` took an action that was certain to be outside the slip, where
    the slip asks for a countersignature and no way to ask for one was
    given. It no longer does.
  - Disclosures handed over beside a Show were ignored where the page
    carried its own. Both are now used together.
  - The note about a late time-stamp on a cancellation appeared for
    almost every block time-stamp. It now goes by the earliest time the
    time-stamp allows.
  - A block's number above about four thousand million was refused,
    against the format description; a header of the wrong length had two
    codes. Both follow the description now, which allows 255 steps in a
    row, as the format's own reader does.
  - Where two passes above a stub both set a limit within a period, the
    checker and the check before acting named different passes. Both now
    name the nearer one.
  - A unit could hold spaces and capitals and be read as the checker's
    own words. A unit is now 1 to 16 characters with no spaces.
  - On a device that cannot check all three signatures of a seal, the
    seal now says that its time-stamp was not counted.

- 2026-10-03: the block time-stamp, a second kind of time-stamp beside a
  seal or a cancellation. It is a proof, in the open format
  OpenTimestamps, that the fingerprint was written into a block of the
  Bitcoin blockchain, with the block's header beside it. The chain is
  used purely as a clock: no coin, wallet, account or payment. It rests
  on SHA-256 only, not on a signature. The person checking names the
  blocks they trust by fingerprint (`blocks`, `--block`); a block's time
  counts as right to within two hours. The library sends nothing
  anywhere and names no service. Tested with made-up blocks; published
  sample proofs of the format were read with the reader, and no complete
  proof from a real service has been checked yet.

- 2026-10-03: faults found by a fifth independent review, of the fixes
  below and of the person's own copy of a cancellation. Each is fixed and
  each is now a test (`test/review5.test.mjs`). The review found no way
  to make a book or a Show read as intact, or as within its slip, when it
  is not, and nothing that crashed or hung.
  - The stub writer let two actions asked for at the same moment both
    pass the check before acting. Its calls now wait for one another.
  - The stub writer put the other side's countersignature into the book
    unchecked; one made with other keys made the whole book fail. It is
    now checked first, and left out if it does not check. `add` adds an
    entry only if the book still passes its check with it.
  - The check before acting allowed an action that could never be
    countersigned where the slip asks for a countersignature. It no
    longer does.
  - A name padded with the blank Braille pattern could draw a line that
    looked like the checker's own, a variation selector passed unmarked,
    and a name could carry the checker's words. Every character that is
    not drawn is now marked, a name or a purpose is shown in quotation
    marks, and the page folds runs of spaces as the command line does.
  - The signer of a slip could cover a name with a value a slip may not
    hold, so that the slip was sound only while the name stayed covered.
    Disclosures that do not pass are now refused and reported apart, and
    the slip is checked as it would be without them.
  - A finding about a period was given twice on a helper's stub where the
    slip and the pass both set such a limit. It is given once.
  - Only four passes were compared for one stub, so two checkers could
    differ on the totals of a pass far up. A fourth pass in a row is now
    refused (`pass-too-deep`), and a stub is compared with every pass
    above its own.
  - Any text was accepted in the place of a covered field. It must now be
    a SHA-256 fingerprint in base64url.
  - Disclosures handed over in the wrong form were ignored without a
    word. They are now refused.
  - The format description said an action may not be dated before the
    last stub "under the slip"; the code, rightly, uses the last stub of
    its own chain. The description is corrected.
  - The notes about the person's own copy of a cancellation said the book
    left it out where the book held it with a broken time-stamp, and did
    not point out a late time-stamp on the copy. Both are corrected.
  - A finding about a period may be given for a stub of another chain
    than the one written last. That is as the format sets out; it is now
    stated.

- 2026-10-03: the person's own copy of a cancellation. The checker takes
  it beside the book (`cancellations`, `--cancellation`). It counts even
  where whoever keeps the book left the cancellation out, or holds it
  with a later time-stamp: every stub that no outside time-stamp shows
  to have existed before it is reported, and the check before acting
  allows nothing under the slip. A copy that does not pass its check is
  a problem, never set aside. The answer has a new member, `held`.

- 2026-10-03: faults found by a fourth independent review, of
  cancelling, vouching, covered fields and passing on. Each is fixed and
  each is now a test (`test/review4.test.mjs`). The review found no way
  to crash the checker, and found the checks of who signed a
  cancellation, a vouching record, a withdrawal and a pass sound.
  - A slip could cover an item of a list: a limit, a condition, an
    action, a service or a key. One signed slip then read differently to
    different readers, and the check before acting allowed anything. An
    item of a list can no longer be covered in a slip.
  - A member named `__proto__` in a slip was accepted, hidden from every
    check, and what it held was inherited unchecked: software names sent
    to the terminal as they were, keys for a service that nobody had
    checked, a stand-in for a covered name. It is now a member like any
    other, and is refused as unknown.
  - A limit "within any period" could be emptied by a later-dated stub in
    a helper's chain. A period now goes by the times the stubs state, in
    whichever chain and at whichever place in the book, and is worked out
    once every stub has been read. The check before acting counts the
    periods of later-dated stubs too.
  - Where the person cancelled twice, only the first cancellation in the
    book counted, and whoever kept the book chose the order. Every
    cancellation now counts.
  - A time-stamp beside a cancellation can be swapped for a later one.
    No check can show that; the checker now points out a time-stamp dated
    more than 300 seconds after the cancellation's own date, and the
    documents state the limit.
  - A helper could pass on and so escape the limits, actions and times of
    its own pass. A stub is now compared with every pass above its own,
    and so is an action in the check before acting.
  - A Show applied the strict rule for a time-stamped cancellation, which
    single pages cannot settle, and reported a stub that the whole book
    clears. It now uses only the place of each page, and says so.
  - A Show did not say that a cancellation or a withdrawal may be on a
    page that is not shown. It does now.
  - A vouching record that had run out still stood behind a slip that
    began inside its time. It must now be in force for the whole of the
    slip's time, and for a seal at the time-stamped time too.
  - A pass that the device could not check, with no stub under it, still
    gave "within its slip". It no longer does.
  - Looking up who vouches took time that grew with the number of
    vouching records multiplied by the number of names. It no longer does:
    a book of 45 megabytes that took 46 seconds takes 4.
  - A service whose id is `constructor` was shown as vouched for by
    "undefined". Every service now has a place of its own in the answer.
  - An empty list of covered fields let a name be absent and shown as
    covered. A list now holds exactly one fingerprint, the fingerprint
    method is named exactly where something is covered, and a decoy is
    not accepted.
  - Disclosures handed over with a page that is not a slip were ignored.
    They are now refused; disclosures for a slip that is not there are
    pointed out.
  - The command-line checker and the page did not show how often a slip
    may be passed on. They do now.
  - The type declarations said a covered name is always text, and left
    out the pass on a helper's stub. Both are corrected.
  - Also: a disclosure for a slip must be JSON in the canonical form, so
    that two checkers cannot read one disclosure in two ways.

- 2026-10-03: `openRecorder`, the stub writer beside an agent. It keeps the
  agent's place in its chain, asks the check before acting, takes the
  action only if the answer is yes, and writes the stub.
- 2026-10-03: faults found by a third independent review, of the seal
  and the time-stamp. Each is fixed and each is now a test
  (`test/review3.test.mjs`). The review found no way to have a time-stamp
  counted without the trusted service's key, and nothing that crashed.
  - A Show under a seal did not report a page dated after the time-stamp
    that covers it. It does now, for a countersignature's and an
    approval's date too.
  - A seal shown as a single page was compared with nothing. Its place is
    now checked, the page says it could not be compared, and its
    time-stamp is credited to no other page.
  - On the checking page, a line that was not a fingerprint was dropped,
    which switched the check off. It now stops the check and says which
    box.
  - A time-stamp from a service nobody named could make a sound record
    fail. It is now compared with nothing.
  - A time-stamp is now read in full and must be strict DER, laid out as
    its standards set out. It must name the certificate that signed it,
    in its signed part; that certificate, wherever it sits, is the one
    that counts. A time-stamp that states its time too loosely, or carries
    an extension it insists on, is refused.
  - A seal dated before an entry it covers, and a later seal time-stamped
    before an earlier one, are reported.
  - A time-stamp is credited only when all three signatures of the seal
    were checked.
  - A name padded with spaces could wrap into a line that looked like the
    checker's own. Runs of spaces are now shown as one.
  - Smaller: the same time-stamp twice is refused; checking a time-stamp
    no longer changes the caller's copy; a small file can no longer cost
    much work.
- 2026-10-03: passing a slip on. A slip can allow its agent to hand part
  of its permission to a helper agent, up to three times in a row. The
  pass is a new record, signed by the agent that passes on. A helper's
  stubs form a chain of their own and are compared with the pass and with
  the slip; the slip's totals take in the agent and every helper
  together. New codes: `pass-missing`, `pass-mismatch` (refused);
  `pass-not-allowed`, `pass-wider` (reported).
- 2026-10-03: covered fields. A slip can be written with its names and
  its purpose covered, by the standard "Selective Disclosure for JSON Web
  Tokens" (RFC 9901) as it stands. A reader sees a covered field only if
  handed its disclosure; the signature, the chain and the tree check
  either way. The standard's worked example is a test, with every case
  the standard says must be rejected. New: `prepareSlip(fields, { cover })`,
  the `disclosures` option, disclosures on a page of a Show,
  `--disclosures`, and the code `cover-invalid`.
- 2026-10-03: type declarations for the whole library, for the checker
  alone and for the browser's passkey part. Checked once with a type
  checker against a developer's use of the library; a test keeps them in
  step with what the library exports.
- 2026-10-03: cancelling a slip, and vouching for a name.
  - The person who signed a slip can cancel it with the same passkey, and
    have the cancellation time-stamped at once. Stubs after it are
    reported (`after-cancellation`). With a time-stamp on the
    cancellation, a stub counts as earlier only if an outside time-stamp
    shows that it existed by then.
  - A vouching record: an organisation states that a key belongs to a
    name, for a person, an agent, a service or a recorder. The person
    checking says which organisations they trust (`vouchers`,
    `--voucher`), and a name those vouch for is shown as vouched for.
    The organisation can withdraw the record.
  - A slip may state the fingerprints of the agent's program and
    settings. It is shown as a statement, not as proof of what ran.
  - Three new records, with their own labels: the cancellation, the
    vouching record and the withdrawal.
- 2026-10-03: faults found by a second independent review, of the
  framework of limits. Each is fixed and each is now a test. The review
  found no way to make a whole book read as intact, or as within its
  slip, when it was not.
  - The check before acting allowed an action dated before the last stub,
    which then broke the book. It allowed an action on a device that
    could check only one signature of two. It allowed an action under a
    slip signed by any key. It now refuses all three, must be told whose
    passkey it trusts, and where the slip asks for the person's approval
    allows the action only with the signed approval in hand.
  - A Show did not say that single pages cannot show an approval used
    twice. It now says so.
  - A stub or a refusal under a slip that the device could not confirm
    was shown as if it were evidence. It is now hidden.
  - A service's terms signed by a stranger, under the service's name,
    were shown with nothing to tell them apart. Terms and refusals now
    show the fingerprint of the keys that signed them.
  - An approval's own date was compared with nothing and shown nowhere.
    It is now shown, and an approval dated later than its stub is
    refused (`approval-dated-after-stub`).
  - Characters that cannot be seen (zero-width characters, soft hyphens,
    line separators) passed through to the screen. They are now shown as
    a mark, as control characters already were.
  - The name of an unknown field was copied into the message about it.
    No word from a record goes into a message now.
  - The format description said less than the code about which letters a
    unit and an action name may hold. It now says the same.
  - Smaller: an approval whose number equals another record's number was
    called "reused"; terms could accept what they forbid; a service could
    not write down a refused request for an unlisted reserved name; a
    period kept everything it had ever counted in memory.
- 2026-10-03: the Seal and the outside time-stamp.
  - A seal is a new record: whoever keeps a book signs its top
    fingerprint and its number of entries, with three signatures
    (Ed25519, ML-DSA-87 and SLH-DSA-SHA2-256s). Each seal names the one
    before it.
  - A seal may carry up to four time-stamps in the standard form of RFC
    3161. The checker reads them offline with a small strict reader of
    its own, and trusts a service only by the fingerprint of its
    certificate, which the person checking gives. No service is named
    anywhere.
  - The latest stubs before a seal can no longer be removed unnoticed. An
    entry dated later than the time-stamp that covers it is reported.
  - A Show can be made under a seal, and then proves when its pages
    existed with no other copy of the top fingerprint.
  - New options: `sealKeys`, `stampServices`, `--sealer`,
    `--stamp-service`. The checking page has boxes for what the person
    trusts.
  - Tested against time-stamps made by the OpenSSL program.
  - What is still open: the last seal, with everything after it, can be
    removed unnoticed, unless someone else holds a copy.
- 2026-10-03: a framework of limits, in five layers.
  - Amounts: besides a total, a slip can limit each single action, the
    number of actions, and a total or a number within any period.
  - Boundaries: a slip can ask that the other side countersign an action.
  - Approvals: a slip can ask for the person's own approval of an action,
    always or above an amount. The approval is a new record, signed with
    the same passkey as the slip, for exactly one action.
  - Stated rules: a slip can name kinds of action the agent must never
    do, which a checker compares with the stubs, and rules of conduct,
    which are the person's signed instruction.
  - The other side's records: a service can sign a refusal, and its terms
    for agents. Both are new records.
  - A shared list of 30 action names in 8 kinds, a first draft. Names
    that begin `provared.` are reserved for it.
  - `checkBefore`: would this action be outside the slip? It uses the
    checker's own comparison.
  - The demonstration and the sample record show all of these. The
    person approves one order with the passkey.
  - Every slip now holds `requires` and `never`, so a draft slip written
    before this change no longer checks.
- 2026-10-03: the quantum-safe method for agents and services is now
  ML-DSA-87, the strongest of the three strengths of FIPS 204, in place
  of ML-DSA-65. The test uses the ML-DSA-87 worked example of RFC 9964.
  The sample record was made again. A key set is larger, so one slip now
  holds about a dozen services with keys at most.
- 2026-10-03: the checking page marks the agent's name and the services'
  names as labels that are not checked, as it already did for the
  person's name.
- 2026-10-03: faults found by an independent review, each fixed and each
  now a test.
  - A small record made with no key crashed the checker (content whose
    "type" was not text). Nothing from a record is put into a message
    unchecked any more, and anything the checker does not expect is
    reported as the problem `check-failed`, never as a pass.
  - "Intact" was reported on a device that could check no signature. It
    is now said only when no problem was found and every signature was
    checked; `summary.problemFound` says whether a problem was found. An
    entry none of whose signatures could be checked is not shown and not
    compared with its slip.
  - A Show reported "within its slip" for a single stub over the limit.
  - "Every signature checked" was reported when nothing was checked.
  - A flood of line feeds could end the process. Lines are now counted as
    they are split.
  - A trusted top fingerprint was ignored for a book, and a trusted number
    of entries could not be given: `expectedRoot`, `expectedSize`,
    `--root`, `--size`.
  - The writers could make a slip too large for the checker.
  - `--json` printed characters that can disturb a terminal; the page did
    not neutralise characters that reorder text.
  - Smaller: an RSA key of 2,041 bits was accepted; lengths were counted
    in a way that differs between languages; the threat model said only
    "the end" of a book could be removed.
- 2026-10-03: a damaged record no longer reads as "every signature
  checked"; what a failed entry says is no longer shown.
- 2026-10-03: the pages no longer scroll sideways on a phone; times are
  shown in words.
- 2026-10-03: the first build.
  - `docs/threat-model.md`: who might attack a record, what each part
    protects and what it does not, written before the code.
  - `spec/provared-format.md`: the format, draft version 0: the Slip, the
    Stub, the countersignature, the chain, the book, the tree and the
    Show.
  - `src/`: the checker (`checkBook`, `checkShow`, `checkSlip`) and the
    writers (`prepareSlip`, `assembleSlip`, `writeStub`, `countersign`,
    `writeBook`, `makeShow`), with no dependencies. Agents and services
    sign with Ed25519 and ML-DSA-65 together; a person signs a slip with
    a passkey.
  - `bin/provared-check.mjs`: the checker for the command line.
  - `page/`: the checking page and the demonstration page.
  - `demo/`: the demonstration, an invented office agent that orders
    supplies within a limit, with a local server.
  - `samples/`: a sample record written once, and what a checker must
    find in it.
  - `test/`: the tests, including the worked examples of RFC 8032, RFC
    8037, RFC 9964 and the test trees of RFC 6962, and one test for every
    refusal the threat model lists.
  - Licences: Apache License 2.0 for the code, Creative Commons
    Attribution 4.0 for the documents.
- 2026-10-03: the folder created; no code yet.
- 2026-10-03: named Provared.
