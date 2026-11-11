export const meta = {
  name: 'pt-slice-pipeline-v2',
  description: 'Implement or resume PatchTrace slices in pre-created worktrees, with model fallback, independent adversarial review and bounded fix rounds',
  phases: [
    { title: 'Implement', detail: 'red/green implementation (or resume), local commits only' },
    { title: 'Review', detail: 'two independent reviewers per slice (correctness, safety)' },
    { title: 'Fix', detail: 'author addresses blocker/major findings, then re-review' },
  ],
}
const IMPL = {
  type: 'object',
  properties: {
    status: { type: 'string', enum: ['done', 'partial', 'blocked'] },
    branch: { type: 'string' },
    commits: { type: 'array', items: { type: 'object', properties: { sha: { type: 'string' }, subject: { type: 'string' } }, required: ['sha', 'subject'] } },
    files_changed: { type: 'array', items: { type: 'string' } },
    tests_added: { type: 'array', items: { type: 'string' } },
    red_evidence: { type: 'string' },
    focused_tests: { type: 'string' },
    ruff: { type: 'string' },
    schemas_regenerated: { type: 'string' },
    spec_amendments: { type: 'array', items: { type: 'string' } },
    deviations: { type: 'string' },
    integrator_asks: { type: 'array', items: { type: 'string' } },
    tracker_rows: { type: 'string' },
    open_risks: { type: 'array', items: { type: 'string' } },
    unverified: { type: 'array', items: { type: 'string' } },
  },
  required: ['status', 'branch', 'commits', 'files_changed', 'tests_added', 'red_evidence', 'focused_tests', 'ruff', 'schemas_regenerated', 'spec_amendments', 'deviations', 'integrator_asks', 'tracker_rows', 'open_risks', 'unverified'],
}
const REVIEW = {
  type: 'object',
  properties: {
    verdict: { type: 'string', enum: ['approve', 'approve-with-nits', 'changes-required'] },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          severity: { type: 'string', enum: ['blocker', 'major', 'minor', 'nit'] },
          location: { type: 'string' },
          issue: { type: 'string' },
          reproduction: { type: 'string' },
          fix: { type: 'string' },
        },
        required: ['severity', 'location', 'issue', 'reproduction', 'fix'],
      },
    },
    checks_run: { type: 'string' },
    summary: { type: 'string' },
  },
  required: ['verdict', 'findings', 'checks_run', 'summary'],
}
const LENSES = [
  { key: 'correctness', focus: 'correctness on edge cases and adversarial inputs the author did not test; whether each red test truly fails on origin/main for the stated reason; whether each fix actually closes the finding it names; test quality (real assertions, hermetic, deterministic)' },
  { key: 'safety', focus: 'regressions in existing behaviour and in the existing tests of every touched module; security and data integrity (untrusted input, error paths, resource bounds, partial writes); contract, spec and schema consistency; Windows portability; scope (file ownership, frozen shared files, other sessions lanes); ruff' },
]
const { scratch, slices } = args
const IMPL_MODELS = args.impl_models || ['default']  // per-slice override: s.impl_models
const REVIEW_MODELS = args.review_models || ['default']  // per-slice override: s.review_models

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

const head = s => `Slice ${s.id}. Worktree: ${s.worktree} (branch ${s.branch}, based on origin/main 882d1ca0). Slice card: ${s.card}.`
const implPrompt = s =>
  `You are the implementation worker for one PatchTrace slice.\n${head(s)}\n` +
  `Read ${scratch}/briefs/IMPL-COMMON.md first (binding; note its section "Resuming an interrupted attempt": this worktree may already hold commits or uncommitted changes from an interrupted earlier attempt), then the card, then do the work and commit locally in the worktree. Return the structured report for the whole slice.`
const reviewPrompt = (s, lens, report, round) =>
  `You are an independent reviewer (lens: ${lens.key}) of one PatchTrace slice, review round ${round}.\n${head(s)}\n` +
  `Read ${scratch}/briefs/REVIEW-COMMON.md first (binding).\nYour lens: ${lens.focus}.\n` +
  (typeof report === 'string'
    ? `The author's report is in the file ${report} (a claim to verify, not a fact).\n`
    : `The author's report (a claim to verify, not a fact):\n${JSON.stringify(report)}\n`) +
  (round > 1 ? 'This is a re-review after fixes: verify that each earlier blocking finding is really closed and look for regressions the fixes introduced.\n' : '') +
  `Return the structured review.`
const fixPrompt = (s, blocking, minor, round) =>
  `You are the implementation worker for PatchTrace slice ${s.id}, fix round ${round}.\n${head(s)}\n` +
  `Read ${scratch}/briefs/IMPL-COMMON.md (binding) and the card again. Independent reviewers found the problems below. For each one: reproduce it, add or extend a test that fails because of it, fix it, and commit locally (new commits only; never amend or rewrite history). If a finding is wrong, show the evidence instead of changing code.\n` +
  `BLOCKING FINDINGS:\n${JSON.stringify(blocking)}\n` +
  `MINOR FINDINGS (fix when cheap and clearly correct; otherwise list them under open_risks):\n${JSON.stringify(minor)}\n` +
  `Return the full structured report for the slice as it now stands (all commits, not only the new ones).`

const results = await pipeline(
  slices,
  async s => {
    if (s.skip_impl) return s.report_path
    return tryAgent(implPrompt(s), { label: `impl:${s.id}`, phase: 'Implement', schema: IMPL, effort: s.effort || 'high' }, s.impl_models || IMPL_MODELS)
  },
  async (impl, s) => {
    if (!impl) return { slice: s.id, branch: s.branch, worktree: s.worktree, verdict: 'implement-failed' }
    let report = impl
    const rounds = []
    let verdict = 'unresolved'
    for (let round = 1; round <= 3; round++) {
      const reviews = (await parallel(LENSES.map(lens => () =>
        tryAgent(reviewPrompt(s, lens, report, round), { label: `review:${s.id}:${lens.key}:r${round}`, phase: 'Review', schema: REVIEW, effort: 'high' }, s.review_models || REVIEW_MODELS)
          .then(r => (r ? { lens: lens.key, ...r } : null))))).filter(Boolean)
      const all = reviews.flatMap(r => (r.findings || []).map(f => ({ lens: r.lens, ...f })))
      const blocking = all.filter(f => f.severity === 'blocker' || f.severity === 'major')
      const minor = all.filter(f => f.severity === 'minor')
      rounds.push({ round, reviews })
      if (reviews.length === 0) { verdict = 'review-failed'; break }
      if (blocking.length === 0) { verdict = minor.length ? 'approved-with-minors' : 'approved'; break }
      if (round === 3) { verdict = 'unresolved'; break }
      const fixed = await tryAgent(fixPrompt(s, blocking, minor, round), { label: `fix:${s.id}:r${round}`, phase: 'Fix', schema: IMPL, effort: s.effort || 'high' }, s.impl_models || IMPL_MODELS)
      if (!fixed) { verdict = 'fix-failed'; break }
      report = fixed
    }
    return { slice: s.id, branch: s.branch, worktree: s.worktree, verdict, report: typeof report === 'string' ? { report_file: report } : report, rounds }
  }
)
return results.map((r, i) => r || { slice: slices[i].id, verdict: 'pipeline-error' })
