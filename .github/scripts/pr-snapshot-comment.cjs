const marker = '<!-- scfw-pr-snapshot -->';
const platforms = [
  ['macOS', 'darwin', 'arm64'],
  ['macOS', 'darwin', 'amd64'],
  ['Linux', 'linux', 'arm64'],
  ['Linux', 'linux', 'amd64'],
];

module.exports = async ({ github, context, core }) => {
  const run = context.payload.workflow_run;
  if (run.event !== 'pull_request' || run.conclusion !== 'success') return;

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
  }

  const artifacts = await github.paginate(github.rest.actions.listWorkflowRunArtifacts, {
    ...repo,
    run_id: run.id,
    per_page: 100,
  });

  for (const candidate of candidates) {
    // One commit may belong to several PRs; this run only built one PR.
    const prefix = `scfw-snapshot-pr-${candidate.number}-`;
    if (!artifacts.some(artifact => artifact.name.startsWith(prefix))) continue;

    const { data: pr } = await github.rest.pulls.get({ ...repo, pull_number: candidate.number });
    if (pr.state !== 'open' || pr.head.sha !== run.head_sha ||
        pr.base.repo.full_name !== `${repo.owner}/${repo.repo}`) {
      core.info(`Skipping PR #${candidate.number}: the run no longer matches its open head.`);
      continue;
    }

    const downloads = platforms.map(([os, goos, arch]) => {
      const name = `scfw-snapshot-pr-${pr.number}-${goos}-${arch}`;
      const matches = artifacts.filter(artifact => artifact.name === name && !artifact.expired);
      if (matches.length !== 1) throw new Error(`Expected one unexpired artifact named ${name}`);
      const url = `${context.serverUrl}/${repo.owner}/${repo.repo}/actions/runs/${run.id}/artifacts/${matches[0].id}`;
      return `| ${os} | ${arch} | [${name}](${url}) |`;
    });

    const comments = await github.paginate(github.rest.issues.listComments, {
      ...repo,
      issue_number: pr.number,
      per_page: 100,
    });
    const existing = comments.find(comment => comment.user?.login === 'github-actions[bot]' &&
      comment.user.type === 'Bot' && comment.body?.startsWith(marker));
    // A rerun or a delayed completion must not replace a newer run's links,
    // even when both runs built the same commit.
    const previous = existing?.body.match(/<!-- scfw-pr-snapshot-run:(\d+):(\d+) -->/);
    if (previous && (Number(previous[1]) > run.id ||
        (Number(previous[1]) === run.id && Number(previous[2]) > run.run_attempt))) {
      core.info(`Skipping older snapshot run ${run.id}, attempt ${run.run_attempt}.`);
      continue;
    }

    const body = [
      marker,
      `<!-- scfw-pr-snapshot-run:${run.id}:${run.run_attempt} -->`,
      '### SCFW PR snapshot',
      '',
      `Built from PR head commit \`${run.head_sha}\` ([build](${context.serverUrl}/${repo.owner}/${repo.repo}/actions/runs/${run.id})).`,
      '',
      '| OS | Architecture | Binary download |',
      '| --- | --- | --- |',
      ...downloads,
      '',
      'These are direct binary downloads, with no archive to extract. Sign in to GitHub to download; artifacts expire after 30 days.',
      'After downloading, make the binary executable with `chmod +x scfw-snapshot-pr-*` and run it with `--help`.',
    ].join('\n');

    // Recheck after the metadata requests so a push during this job is skipped.
    const { data: latest } = await github.rest.pulls.get({ ...repo, pull_number: pr.number });
    if (latest.state !== 'open' || latest.head.sha !== run.head_sha) continue;

    if (existing) {
      await github.rest.issues.updateComment({ ...repo, comment_id: existing.id, body });
    } else {
      await github.rest.issues.createComment({ ...repo, issue_number: pr.number, body });
    }
  }
};
