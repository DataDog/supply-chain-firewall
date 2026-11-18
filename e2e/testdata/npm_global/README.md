# Global npm installations

These cases belong to `npm-projects` and compare the real pinned npm command
with SCFW in resolution and proxy modes. `global-workspace-member` first installs
the exact target in a workspace member, retains the bootstrap HTTP download and
installed metadata, then uses a fresh case-owned cache and global destination.
Both ALLOW and BLOCK must evaluate the global registry target even though the
member already has that version.

`global-self` executes `npm install -g --install-links` without a package operand.
The source package has a discovered real registry dependency; ALLOW must match
native global installed state, and BLOCK must prevent that dependency. Source
manifest/lock bytes must remain unchanged. The source itself is local and is
separate from registry targets in policy and artifact assertions.

Set `npm-install-links-v8.8` only for a verified npm version at least 8.8.0.
Earlier versions lack install-links and emit explicit N/A for these four cases.
The global-member cases retain `npm-projects-v7`. All public inputs are selected
and revalidated by the shared real-registry project discovery.
