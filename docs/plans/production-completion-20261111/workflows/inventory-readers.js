export const meta = {
  name: 'pt-inventory-readers-v2',
  description: 'Re-run interrupted read-only inventory analysts with a model fallback chain',
  phases: [{ title: 'Read', detail: 'one analyst per workstream, writes scratchpad/inventory/<key>.json' }],
}
const SUMMARY = {
  type: 'object',
  properties: {
    workstream: { type: 'string' },
    file: { type: 'string' },
    feature_count: { type: 'integer' },
    actionable_count: { type: 'integer' },
    completion: {
      type: 'object',
      properties: {
        implementation_pct: { type: 'number' },
        validation_pct: { type: 'number' },
        basis: { type: 'string' },
      },
      required: ['implementation_pct', 'validation_pct', 'basis'],
    },
    top_actionable: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          title: { type: 'string' },
          size: { type: 'string' },
          priority: { type: 'integer' },
          files: { type: 'array', items: { type: 'string' } },
          lane_conflict: { type: 'string' },
        },
        required: ['id', 'title', 'size', 'priority', 'files', 'lane_conflict'],
      },
    },
    critical_defects: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          severity: { type: 'string' },
          summary: { type: 'string' },
          evidence: { type: 'string' },
        },
        required: ['id', 'severity', 'summary', 'evidence'],
      },
    },
    external_blockers: { type: 'array', items: { type: 'string' } },
    summary: { type: 'string' },
  },
  required: ['workstream', 'file', 'feature_count', 'actionable_count', 'completion', 'top_actionable', 'critical_defects', 'external_blockers', 'summary'],
}
const { scratch, readers } = args
phase('Read')
async function tryAgent(prompt, opts, models) {
  for (const m of models) {
    const o = m === 'default' ? opts : { ...opts, model: m, label: `${opts.label}@${m}` }
    try {
      const r = await agent(prompt, o)
      if (r) return r
    } catch (e) {
      log(`${opts.label}: failed on ${m}`)
    }
  }
  return null
}
const results = await parallel(readers.map(r => () =>
  tryAgent(
    `You are inventory analyst "${r.key}" for the PatchTrace project.\n` +
    `1. Read the common rules: ${scratch}/briefs/COMMON.md (binding).\n` +
    `2. Read your brief: ${scratch}/briefs/${r.key}.md and do exactly that work, thoroughly.\n` +
    `OUTFILE: ${scratch}/inventory/${r.key}.json\n` +
    `An earlier analyst on this workstream was interrupted: if ${scratch}/inventory/tmp-${r.key}/ holds notes or partial results, read them first and reuse what you can verify.\n` +
    `Additional lanes owned by other sessions since the common rules were written (no actionable_now task inside them): rules and call-graph bug fixes (src/patchtrace/rules/**, src/patchtrace/callgraph/**, branch claude/bugfix-rules-cg-rest-20261111); instance B (src/patchtrace/intelligence/tools/capa.py and runner.py, src/patchtrace/search/saved.py); instance C (tools/unified/bench.py, tools/unified/parity.py). This session (sleepy-fermi) is already implementing: the security backlog items TB-09/10/12/15/16, WP-03, PE-2/3/6/7/8; KBA-06/07/08 and the KB dock loader; rz-diff singleton ownership, BinDiff row cap, Diaphora SQLite guard; headless project/compare/corrections/review/profile/doctor/runtime CLI verbs; test-reliability items. Do not list those again as actionable; list only what is new.\n` +
    `Your final structured output must describe what you wrote to OUTFILE (set "workstream" to "${r.key}" and "file" to the OUTFILE path).`,
    { label: `inventory:${r.key}`, phase: 'Read', schema: SUMMARY, effort: 'high' },
    r.models
  ).then(res => (res ? { key: r.key, ...res } : { key: r.key, failed: true }))
))
const done = results.filter(Boolean)
log(`${done.filter(r => !r.failed).length}/${readers.length} analysts returned`)
return done
