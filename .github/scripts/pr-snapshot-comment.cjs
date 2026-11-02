const marker = '<!-- scfw-pr-snapshot -->';
const platforms = [
  ['macOS', 'darwin', 'arm64'],
  ['macOS', 'darwin', 'amd64'],
  ['Linux', 'linux', 'arm64'],
  ['Linux', 'linux', 'amd64'],
];

module.exports = async ({ github, context, core }) => {
  const run = context.payload.workflow_run;
  if (run.event !== 'pull_request') return;

  const repo = context.repo;
  // Fork runs can have an empty pull_requests array. Resolve them through the
  // commit association API, then verify the current PR state below.
  let candidates = run.pull_requests;
  if (!candidates?.length) {
    candidates = await github.paginate(github.rest.repos.listPullRequestsAssociatedWithCommit, {
      ...repo,
      commit_sha: run.head_sha,
      per_page: 100,
    });
    // Failed fork builds may have no artifacts, and the same branch can open
    // PRs against multiple base branches. Read the PR identity from the job
    // name for this exact attempt rather than guessing from the head commit.
    const jobs = await github.paginate(github.rest.actions.listJobsForWorkflowRunAttempt, {
      ...repo,
      run_id: run.id,
      attempt_number: run.run_attempt,
      per_page: 100,
    });
    const numbers = new Set(jobs.flatMap(job => {
      const match = job.name.match(/^Snapshot for PR #(\d+)$/);
      return match ? [Number(match[1])] : [];
    }));
    if (numbers.size !== 1) {
      core.info(`Skipping run ${run.id}: the triggering fork PR is ambiguous.`);
      return;
    }
    candidates = candidates.filter(candidate => numbers.has(candidate.number));
  }

  // A failed build may not have uploaded anything. It must still retire any
  // published snapshot for the current head, including for fork PRs.
  const succeeded = run.conclusion === 'success';
  const artifacts = succeeded ? await github.paginate(github.rest.actions.listWorkflowRunArtifacts, {
    ...repo,
    run_id: run.id,
    per_page: 100,
  }) : [];

  for (const candidate of candidates) {
    // One commit may belong to several PRs; a successful run only built one.
    const prefix = `scfw-snapshot-pr-${candidate.number}-`;
    if (succeeded && !artifacts.some(artifact => artifact.name.startsWith(prefix))) continue;

    const { data: pr } = await github.rest.pulls.get({ ...repo, pull_number: candidate.number });
    if (pr.state !== 'open' || pr.head.sha !== run.head_sha ||
        pr.head.ref !== run.head_branch || pr.head.repo?.id !== run.head_repository?.id ||
        pr.base.repo.full_name !== `${repo.owner}/${repo.repo}`) {
      core.info(`Skipping PR #${candidate.number}: the run no longer matches its open head.`);
      continue;
    }

    const comments = await github.paginate(github.rest.issues.listComments, {
      ...repo,
      issue_number: pr.number,
      per_page: 100,
    });
    const existing = comments.find(comment => comment.user?.login === 'github-actions[bot]' &&
      comment.user.type === 'Bot' && comment.body?.startsWith(marker));

    // A rerun or a delayed completion must not replace a newer run's status,
    // even when both runs built the same commit.
    const previous = existing?.body.match(/<!-- scfw-pr-snapshot-run:(\d+):(\d+) -->/);
    if (previous && (Number(previous[1]) > run.id ||
        (Number(previous[1]) === run.id && Number(previous[2]) > run.run_attempt))) {
      core.info(`Skipping older snapshot run ${run.id}, attempt ${run.run_attempt}.`);
      continue;
    }

    const buildUrl = `${context.serverUrl}/${repo.owner}/${repo.repo}/actions/runs/${run.id}/attempts/${run.run_attempt}`;
    let details;
    if (succeeded) {
      const downloads = platforms.map(([os, goos, arch]) => {
        const name = `scfw-snapshot-pr-${pr.number}-${goos}-${arch}-attempt-${run.run_attempt}`;
        const matches = artifacts.filter(artifact => artifact.name === name && !artifact.expired);
        if (matches.length !== 1) throw new Error(`Expected one unexpired artifact named ${name}`);
        const url = `${context.serverUrl}/${repo.owner}/${repo.repo}/actions/runs/${run.id}/artifacts/${matches[0].id}`;
        return `| ${os} | ${arch} | [${name}](${url}) |`;
      });
      details = [
        `Built from PR head commit \`${run.head_sha}\` ([build](${buildUrl})).`,
        '',
        '| OS | Architecture | Binary download |',
        '| --- | --- | --- |',
        ...downloads,
        '',
        'These are direct binary downloads, with no archive to extract. Sign in to GitHub to download; artifacts expire after 30 days.',
        'After downloading, make the binary executable with `chmod +x scfw-snapshot-pr-*` and run it with `--help`.',
      ];
    } else {
      details = [
        '**Snapshot unavailable for the latest PR head. Previous snapshot links have been retired.**',
        '',
        `The [snapshot build](${buildUrl}) for PR head commit \`${run.head_sha}\` finished with status \`${run.conclusion}\`.`,
        'Push a new commit or rerun the build to publish fresh downloads.',
      ];
    }
    const body = [
      marker,
      `<!-- scfw-pr-snapshot-run:${run.id}:${run.run_attempt} -->`,
      '### SCFW PR snapshot',
      '',
      ...details,
    ].join('\n');

    // Recheck after the metadata requests so a push during this job is skipped.
    const { data: latest } = await github.rest.pulls.get({ ...repo, pull_number: pr.number });
    if (latest.state !== 'open' || latest.head.sha !== run.head_sha) continue;
    // The comment may be absent or an earlier publication may have failed.
    // Consult GitHub directly so an old success cannot publish after a newer
    // attempt fails or while that attempt is still running.
    const { data: latestRun } = await github.rest.actions.getWorkflowRun({ ...repo, run_id: run.id });
    if (latestRun.run_attempt !== run.run_attempt || latestRun.status !== 'completed' ||
        latestRun.conclusion !== run.conclusion) continue;

    if (existing) {
      await github.rest.issues.updateComment({ ...repo, comment_id: existing.id, body });
    } else {
      await github.rest.issues.createComment({ ...repo, issue_number: pr.number, body });
    }
  }
};
