// What a book's sealed content says about itself, as the uploader reads it
// when it hands records to the recorder: the renewals and cancellations the
// person's application keeps with the book. The same reading as the
// application's page makes, so that the two agree on what a book holds.

/** What a book says about itself, as the page uses it. */
export function describe(content) {
  const c = content && typeof content === 'object' ? content : {};
  return {
    name: typeof c.name === 'string' ? c.name : null,
    agent: typeof c.agent === 'string' ? c.agent : null,
    trust: c.trust && Array.isArray(c.trust.issuerKeys) && Array.isArray(c.trust.sealKeys) ? c.trust : { issuerKeys: [], sealKeys: [] },
    cancellations: Array.isArray(c.cancellations) ? c.cancellations : [],
    renewals: Array.isArray(c.renewals) ? c.renewals.filter((r) => r && typeof r === 'object' && r.slip && typeof r.fingerprint === 'string') : [],
  };
}
