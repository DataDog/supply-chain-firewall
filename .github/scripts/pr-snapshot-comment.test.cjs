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
        head_sha: 'a'.repeat(40), pull_requests: [{ number: 42 }],
      },
    },
  };
  const pr = {
    number: 42, state: 'open', head: { sha: 'a'.repeat(40) },
    base: { repo: { full_name: 'DataDog/supply-chain-firewall' } },
  };
  const artifacts = ['darwin-arm64', 'darwin-amd64', 'linux-arm64', 'linux-amd64'].map((target, i) => ({
    id: 200 + i, name: `scfw-snapshot-pr-42-${target}`, expired: false,
  }));
  const state = { pr, artifacts, comments: [], associated: [{ number: 42 }], writes: [], queries: [] };
  const github = {
    rest: {
      repos: { listPullRequestsAssociatedWithCommit: 'associated' },
      actions: { listWorkflowRunArtifacts: 'artifacts' },
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
  ['a failed build', f => { f.context.payload.workflow_run.conclusion = 'failure'; }],
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
  f.state.comments = [botComment(`${marker}\n<!-- scfw-pr-snapshot-run:100:1 -->`)];
  await comment(f);
  assert.equal(f.state.writes[0].method, 'update');
  assert.ok(f.state.writes[0].body.includes('scfw-pr-snapshot-run:100:2'));
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
