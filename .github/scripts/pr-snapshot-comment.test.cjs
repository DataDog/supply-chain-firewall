const assert = require('node:assert/strict');
const { test } = require('node:test');
const comment = require('./pr-snapshot-comment.cjs');

const marker = '<!-- scfw-pr-snapshot -->';

function fixture() {
  const context = {
    repo: { owner: 'DataDog', repo: 'supply-chain-firewall' },
    serverUrl: 'https://github.com',
    payload: {
      workflow_run: {
        id: 100, run_attempt: 1, event: 'pull_request', conclusion: 'success',
        head_sha: 'a'.repeat(40), head_branch: 'snapshot-test', head_repository: { id: 1 }, pull_requests: [{ number: 42 }],
      },
    },
  };
  const pr = {
    number: 42, state: 'open', head: { sha: 'a'.repeat(40), ref: 'snapshot-test', repo: { id: 1 } },
    base: { repo: { full_name: 'DataDog/supply-chain-firewall' } },
  };
  const artifacts = ['darwin-arm64', 'darwin-amd64', 'linux-arm64', 'linux-amd64'].map((target, i) => ({
    id: 200 + i, name: `scfw-snapshot-pr-42-${target}-attempt-1`, expired: false,
  }));
  const state = { pr, artifacts, jobs: [{ name: 'Snapshot for PR #42' }], comments: [], associated: [{ number: 42 }], writes: [], queries: [] };
  const github = {
    rest: {
      repos: { listPullRequestsAssociatedWithCommit: 'associated' },
      actions: {
        listWorkflowRunArtifacts: 'artifacts',
        listJobsForWorkflowRunAttempt: 'jobs',
        getWorkflowRun: async () => ({ data: state.latestRun ?? { ...context.payload.workflow_run, status: 'completed' } }),
      },
      pulls: { get: async () => ({ data: state.pr }) },
      issues: {
        listComments: 'comments',
        createComment: async params => state.writes.push({ method: 'create', ...params }),
        updateComment: async params => state.writes.push({ method: 'update', ...params }),
      },
    },
    paginate: async (method, params) => {
      state.queries.push({ method, ...params });
      return state[method];
    },
  };
  return { context, github, core: { info() {} }, state };
}

function botComment(body, id = 300) {
  return { id, body, user: { login: 'github-actions[bot]', type: 'Bot' } };
}

test('creates a comment linking all four raw binaries from the completed run', async () => {
  const f = fixture();
  await comment(f);
  assert.equal(f.state.writes.length, 1);
  const write = f.state.writes[0];
  assert.equal(write.method, 'create');
  assert.equal(write.issue_number, 42);
  assert.ok(write.body.startsWith(marker));
  assert.ok(write.body.includes('a'.repeat(40)));
  for (const artifact of f.state.artifacts) {
    assert.ok(write.body.includes(`[${artifact.name}](https://github.com/DataDog/supply-chain-firewall/actions/runs/100/artifacts/${artifact.id})`));
  }
  assert.ok(write.body.includes('Sign in to GitHub'));
  assert.ok(write.body.includes('30 days'));
  assert.ok(f.state.queries.some(query => query.method === 'artifacts' && query.run_id === 100));
});

test('updates the existing bot comment without trusting a user-supplied marker', async () => {
  const f = fixture();
  f.state.comments = [
    { id: 299, body: marker, user: { login: 'someone', type: 'User' } },
    botComment(`${marker}\nold links`),
  ];
  await comment(f);
  assert.equal(f.state.writes.length, 1);
  assert.equal(f.state.writes[0].method, 'update');
  assert.equal(f.state.writes[0].comment_id, 300);
});

test('resolves fork PRs with an empty event association using the commit API', async () => {
  const f = fixture();
  f.context.payload.workflow_run.pull_requests = [];
  await comment(f);
  assert.ok(f.state.queries.some(query => query.method === 'associated' && query.commit_sha === 'a'.repeat(40)));
  assert.equal(f.state.writes.length, 1);
});

for (const [name, change] of [
  ['a newer head', f => { f.state.pr.head.sha = 'b'.repeat(40); }],
  ['a closed PR', f => { f.state.pr.state = 'closed'; }],
  ['a different base repository', f => { f.state.pr.base.repo.full_name = 'someone/else'; }],
  ['a non-PR build', f => { f.context.payload.workflow_run.event = 'push'; }],
]) {
  test(`does not comment for ${name}`, async () => {
    const f = fixture();
    change(f);
    await comment(f);
    assert.equal(f.state.writes.length, 0);
  });
}

for (const [name, change] of [
  ['missing', f => { f.state.artifacts.pop(); }],
  ['expired', f => { f.state.artifacts[0].expired = true; }],
  ['duplicate', f => { f.state.artifacts.push(f.state.artifacts[0]); }],
]) {
  test(`rejects ${name} artifacts instead of publishing incomplete downloads`, async () => {
    const f = fixture();
    change(f);
    await assert.rejects(comment(f), /Expected one unexpired artifact/);
    assert.equal(f.state.writes.length, 0);
  });
}

test('does not replace a newer run or rerun with a delayed completion', async () => {
  for (const version of ['101:1', '100:2']) {
    const f = fixture();
    f.state.comments = [botComment(`${marker}\n<!-- scfw-pr-snapshot-run:${version} -->`)];
    await comment(f);
    assert.equal(f.state.writes.length, 0);
  }
});

test('refreshes links for a rerun of the same head commit', async () => {
  const f = fixture();
  f.context.payload.workflow_run.run_attempt = 2;
  const originalArtifacts = [...f.state.artifacts];
  f.state.artifacts.push(...originalArtifacts.map(artifact => ({
    ...artifact, id: artifact.id + 10, name: artifact.name.replace('attempt-1', 'attempt-2'),
  })));
  f.state.comments = [botComment(`${marker}\n<!-- scfw-pr-snapshot-run:100:1 -->`)];
  await comment(f);
  assert.equal(f.state.writes[0].method, 'update');
  assert.ok(f.state.writes[0].body.includes('scfw-pr-snapshot-run:100:2'));
  for (const artifact of originalArtifacts) {
    assert.ok(f.state.artifacts.includes(artifact));
    assert.ok(!f.state.writes[0].body.includes(`/artifacts/${artifact.id})`));
    assert.ok(f.state.writes[0].body.includes(`/artifacts/${artifact.id + 10})`));
  }
});

test('skips a push that arrives while fetching comment metadata', async () => {
  const f = fixture();
  let reads = 0;
  f.github.rest.pulls.get = async () => ({
    data: ++reads === 1 ? f.state.pr : { ...f.state.pr, head: { sha: 'b'.repeat(40) } },
  });
  await comment(f);
  assert.equal(reads, 2);
  assert.equal(f.state.writes.length, 0);
});

test('ignores other PRs sharing the same head commit when resolving a fork run', async () => {
  const f = fixture();
  f.context.payload.workflow_run.pull_requests = [];
  f.state.associated = [{ number: 43 }, { number: 42 }];
  const reads = [];
  f.github.rest.pulls.get = async ({ pull_number }) => {
    reads.push(pull_number);
    return { data: { ...f.state.pr, number: pull_number } };
  };
  await comment(f);
  assert.deepEqual(reads, [42, 42]);
  assert.equal(f.state.writes.length, 1);
  assert.equal(f.state.writes[0].issue_number, 42);
});


for (const status of ['failure', 'cancelled', 'timed_out', 'action_required']) {
  test(`retires the previous head snapshot when the latest build ends as ${status}`, async () => {
    const f = fixture();
    f.context.payload.workflow_run.conclusion = status;
    f.state.artifacts = [];
    f.state.comments = [botComment(`${marker}\n<!-- scfw-pr-snapshot-run:99:1 -->\nOld head: ${'b'.repeat(40)}\n[old binary](https://github.com/example/artifacts/123)`)];
    await comment(f);
    assert.equal(f.state.writes.length, 1);
    const write = f.state.writes[0];
    assert.equal(write.method, 'update');
    assert.equal(write.comment_id, 300);
    assert.ok(write.body.includes('Snapshot unavailable for the latest PR head'));
    assert.ok(write.body.includes('a'.repeat(40)));
    assert.ok(write.body.includes(`status \`${status}\``));
    assert.ok(!write.body.includes('/artifacts/'));
    assert.ok(!write.body.includes('b'.repeat(40)));
    assert.ok(!f.state.queries.some(query => query.method === 'artifacts'));
  });
}

test('retires a failed fork snapshot with no uploads, excluding unrelated branches and repositories', async () => {
  const f = fixture();
  f.context.payload.workflow_run.conclusion = 'failure';
  f.context.payload.workflow_run.pull_requests = [];
  f.context.payload.workflow_run.head_repository.id = 2;
  f.state.pr.head.repo.id = 2;
  f.state.artifacts = [];
  f.state.associated = [{ number: 43 }, { number: 44 }, { number: 42 }];
  f.state.comments = [botComment(`${marker}\nprevious snapshot links`)];
  f.github.rest.pulls.get = async ({ pull_number }) => ({
    data: {
      ...f.state.pr,
      number: pull_number,
      head: {
        ...f.state.pr.head,
        ref: pull_number === 43 ? 'another-branch' : f.state.pr.head.ref,
        repo: { id: pull_number === 44 ? 3 : 2 },
      },
    },
  });
  await comment(f);
  assert.equal(f.state.writes.length, 1);
  assert.equal(f.state.writes[0].comment_id, 300);
  assert.ok(f.state.writes[0].body.includes('Snapshot unavailable'));
});

test('a failed run from an obsolete head cannot retire the current snapshot', async () => {
  const f = fixture();
  f.context.payload.workflow_run.conclusion = 'cancelled';
  f.state.pr.head.sha = 'b'.repeat(40);
  f.state.comments = [botComment(`${marker}\ncurrent snapshot links`)];
  await comment(f);
  assert.equal(f.state.writes.length, 0);
});

test('delayed failures cannot retire a snapshot from a newer run or attempt', async () => {
  for (const version of ['101:1', '100:2']) {
    const f = fixture();
    f.context.payload.workflow_run.conclusion = 'failure';
    f.state.comments = [botComment(`${marker}\n<!-- scfw-pr-snapshot-run:${version} -->\nnewer downloads`)];
    await comment(f);
    assert.equal(f.state.writes.length, 0);
  }
});

test('a failed rerun retires links and prevents delayed success from restoring them', async () => {
  const f = fixture();
  f.context.payload.workflow_run.conclusion = 'failure';
  f.context.payload.workflow_run.run_attempt = 2;
  f.state.comments = [botComment(`${marker}\n<!-- scfw-pr-snapshot-run:100:1 -->\nold downloads`)];
  await comment(f);
  assert.equal(f.state.writes.length, 1);
  assert.ok(f.state.writes[0].body.includes('Snapshot unavailable'));
  f.state.comments = [botComment(f.state.writes[0].body)];
  f.state.writes = [];
  f.context.payload.workflow_run.conclusion = 'success';
  f.context.payload.workflow_run.run_attempt = 1;
  await comment(f);
  assert.equal(f.state.writes.length, 0);
});

test('a successful retry replaces the unavailable notice using only its own artifact IDs', async () => {
  const f = fixture();
  f.state.comments = [botComment(`${marker}\n<!-- scfw-pr-snapshot-run:100:1 -->\nSnapshot unavailable`)];
  f.context.payload.workflow_run.run_attempt = 2;
  f.state.artifacts.push(...f.state.artifacts.map(artifact => ({
    ...artifact, id: artifact.id + 10, name: artifact.name.replace('attempt-1', 'attempt-2'),
  })));
  await comment(f);
  const body = f.state.writes[0].body;
  assert.ok(!body.includes('Snapshot unavailable'));
  assert.ok(body.includes('attempt-2'));
  for (let i = 0; i < 4; i++) {
    assert.ok(body.includes(`/artifacts/${210 + i})`));
    assert.ok(!body.includes(`/artifacts/${200 + i})`));
  }
});

test('failure to publish a rerun comment leaves previously published artifacts intact', async () => {
  const f = fixture();
  await comment(f);
  const published = f.state.writes[0].body;
  f.state.comments = [botComment(published)];
  f.context.payload.workflow_run.run_attempt = 2;
  f.state.artifacts.push(...f.state.artifacts.map(artifact => ({
    ...artifact, id: artifact.id + 10, name: artifact.name.replace('attempt-1', 'attempt-2'),
  })));
  const before = structuredClone(f.state.artifacts);
  f.github.rest.issues.updateComment = async () => { throw new Error('GitHub API unavailable'); };
  await assert.rejects(comment(f), /GitHub API unavailable/);
  assert.deepEqual(f.state.artifacts, before);
  assert.equal(f.state.comments[0].body, published);
});

test('skips retiring a snapshot if another push arrives while fetching comment metadata', async () => {
  const f = fixture();
  f.context.payload.workflow_run.conclusion = 'failure';
  f.state.comments = [botComment(`${marker}\nold downloads`)];
  let reads = 0;
  f.github.rest.pulls.get = async () => ({
    data: ++reads === 1 ? f.state.pr : { ...f.state.pr, head: { sha: 'b'.repeat(40) } },
  });
  await comment(f);
  assert.equal(reads, 2);
  assert.equal(f.state.writes.length, 0);
});


test('records an unavailable notice even when a failed run has no previous comment', async () => {
  const f = fixture();
  f.context.payload.workflow_run.conclusion = 'failure';
  f.state.artifacts = [];
  await comment(f);
  assert.equal(f.state.writes.length, 1);
  assert.equal(f.state.writes[0].method, 'create');
  assert.ok(f.state.writes[0].body.includes('Snapshot unavailable'));
  assert.ok(f.state.writes[0].body.includes('scfw-pr-snapshot-run:100:1'));
});

test('does not publish a delayed success when a newer attempt failed without publishing a comment', async () => {
  const f = fixture();
  f.state.latestRun = { ...f.context.payload.workflow_run, run_attempt: 2, status: 'completed', conclusion: 'failure' };
  await comment(f);
  assert.equal(f.state.writes.length, 0);
});

test('does not publish a delayed success while a newer attempt is running', async () => {
  const f = fixture();
  f.state.latestRun = { ...f.context.payload.workflow_run, run_attempt: 2, status: 'in_progress', conclusion: null };
  await comment(f);
  assert.equal(f.state.writes.length, 0);
});

test('a failed fork run only retires the triggering PR when another PR targets a different base branch', async () => {
  const f = fixture();
  f.context.payload.workflow_run.conclusion = 'failure';
  f.context.payload.workflow_run.pull_requests = [];
  f.state.artifacts = [];
  f.state.associated = [{ number: 43 }, { number: 42 }];
  const reads = [];
  f.github.rest.pulls.get = async ({ pull_number }) => {
    reads.push(pull_number);
    return { data: {
      ...f.state.pr, number: pull_number,
      base: { ...f.state.pr.base, ref: pull_number === 42 ? 'main' : 'release' },
    } };
  };
  await comment(f);
  assert.deepEqual(reads, [42, 42]);
  assert.equal(f.state.writes.length, 1);
  assert.equal(f.state.writes[0].issue_number, 42);
  assert.ok(f.state.queries.some(query => query.method === 'jobs' && query.run_id === 100 && query.attempt_number === 1));
});

for (const jobs of [[], [{ name: 'Snapshot for PR #42' }, { name: 'Snapshot for PR #43' }]]) {
  test(`skips ambiguous fork PR metadata with ${jobs.length} matching jobs`, async () => {
    const f = fixture();
    f.context.payload.workflow_run.conclusion = 'failure';
    f.context.payload.workflow_run.pull_requests = [];
    f.state.jobs = jobs;
    f.state.comments = [botComment(`${marker}\nvalid downloads`)];
    await comment(f);
    assert.equal(f.state.writes.length, 0);
  });
}
