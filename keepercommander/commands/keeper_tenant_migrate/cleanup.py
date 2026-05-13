"""Cleanup: delete entities matching a prefix on the current tenant.

Ports the `--cleanup` half of migration_scripts/test_comprehensive_setup.sh.
Ordered teardown (records → teams → roles → nodes) so children go before
their parents.

Default prefix is 'MIGTEST-' to match the bash reference. Use explicitly
to target any other prefix — the function enforces that prefix is
non-empty to prevent accidental wipe of an entire tenant.
"""

import logging


class CleanupClient:
    """Protocol for delete operations on the current tenant."""

    def delete_team(self, name):
        raise NotImplementedError

    def delete_role(self, name):
        raise NotImplementedError

    def delete_node(self, name):
        raise NotImplementedError

    def list_entities(self):
        """Return {kind: [{name, ...}, ...]} from params.enterprise.

        May include a 'records' key — list of {title, uid} — when
        the client supports record deletion. May include a
        'shared_folders' key — list of {name, uid} — when the client
        supports SF deletion (Bug 25). Callers must handle absence
        gracefully.
        """
        raise NotImplementedError

    def delete_record(self, uid):
        """Optional: delete a record by UID. Only used when
        --include-records is set. Default is a no-op returning False
        so clients that don't implement it don't need to override."""
        return False

    def delete_shared_folder(self, uid):
        """Optional: delete a shared folder by UID. Default no-op so
        clients that don't implement it (older callers) don't need to
        override. Bug 25 — SFs were missed by the original cleanup
        scope, leaving stale SFs across e2e runs and blocking Bug 22
        validation."""
        return False


class FakeCleanupClient(CleanupClient):
    """In-memory client used by tests.

    Delete methods mutate self.entities so post-delete list_entities()
    reflects the actual state — lets the verify-after-delete path in
    cleanup() run end-to-end against the fake the way it does against
    the Commander-backed client.

    `fail_on` entries cause the delete to silently return True without
    mutating entities — simulating Commander's silent-failure pattern
    ('node has children' → warning, no exception).
    """

    def __init__(self, entities=None, fail_on=None, silent_fail_on=None):
        self.entities = entities or {'teams': [], 'roles': [],
                                      'nodes': [], 'records': [],
                                      'shared_folders': []}
        # Hard fail: delete returns False, entity stays.
        self.fail_on = fail_on or set()
        # Silent fail: delete returns True but entity stays (bug class
        # of --mc / 'node has children' silent warning).
        self.silent_fail_on = silent_fail_on or set()
        self.calls = []

    def _remove(self, kind, predicate):
        self.entities[kind] = [
            e for e in (self.entities.get(kind) or [])
            if not predicate(e)
        ]

    def delete_team(self, name):
        self.calls.append(('team', name))
        if ('team', name) in self.fail_on:
            return False
        if ('team', name) in self.silent_fail_on:
            return True  # silent: entity stays
        self._remove('teams', lambda e: e.get('name') == name)
        return True

    def delete_role(self, name):
        self.calls.append(('role', name))
        if ('role', name) in self.fail_on:
            return False
        if ('role', name) in self.silent_fail_on:
            return True
        self._remove('roles', lambda e: e.get('name') == name)
        return True

    def delete_node(self, name):
        self.calls.append(('node', name))
        if ('node', name) in self.fail_on:
            return False
        if ('node', name) in self.silent_fail_on:
            return True
        self._remove('nodes', lambda e: e.get('name') == name)
        return True

    def delete_record(self, uid):
        self.calls.append(('record', uid))
        if ('record', uid) in self.fail_on:
            return False
        if ('record', uid) in self.silent_fail_on:
            return True
        self._remove('records', lambda e: e.get('uid') == uid)
        return True

    def delete_shared_folder(self, uid):
        self.calls.append(('shared_folder', uid))
        if ('shared_folder', uid) in self.fail_on:
            return False
        if ('shared_folder', uid) in self.silent_fail_on:
            return True
        self._remove('shared_folders', lambda e: e.get('uid') == uid)
        return True

    def list_entities(self):
        return self.entities


def matching_entities(entities, prefix, *, include_records=False):
    """Return the subset of each kind whose name/title starts with prefix."""
    if not prefix:
        raise ValueError('prefix must be non-empty to prevent accidental wipe')
    out = {
        kind: [e for e in (entities.get(kind) or [])
               if (e.get('name') or '').startswith(prefix)]
        for kind in ('teams', 'roles', 'nodes')
    }
    if include_records:
        out['records'] = [
            r for r in (entities.get('records') or [])
            if (r.get('title') or r.get('name') or '').startswith(prefix)
        ]
    # Shared folders are always included when present in the entities
    # projection — they're test-fixture artifacts of structure restore
    # (Bug 25). Clients that don't enumerate SFs simply emit no
    # 'shared_folders' key and the loop in cleanup() short-circuits.
    out['shared_folders'] = [
        sf for sf in (entities.get('shared_folders') or [])
        if (sf.get('name') or '').startswith(prefix)
    ]
    return out


def _still_present(client, kind: str, key: str, value: str) -> bool:
    """Post-delete verification: is the entity still listed by the
    client after we tried to delete it?

    Commander's enterprise-node / enterprise-team / enterprise-role
    commands log warnings ('node has children', etc.) without raising
    on certain failures. The delete call returns success-ish and the
    plugin used to count it as deleted. This helper closes that loop
    by re-querying after each delete and flagging any leftover as an
    error. Mirrors the --mc 'trust but verify' pattern.
    """
    current = (client.list_entities() or {}).get(kind) or []
    return any((e.get(key) or '') == value for e in current)


def cleanup(client, prefix, *, include_records=False, dry_run=False):
    """Delete every entity on current tenant whose name starts with prefix.

    Order: records → shared_folders → teams → roles → nodes (children
    before parents; nodes last since they may hold the teams/roles we
    just deleted).

    Every delete is followed by a live-state check. If the entity is
    still present after the delete call, the row is counted as an
    error regardless of the client's return code — Commander silently
    no-ops some delete paths (e.g. 'node has children' warning)
    and we must not report those as success.

    dry_run=True skips the still-present verify (the dry-run wrapper
    doesn't actually delete, so the entity always remains and would
    falsely count every op as a silent no-op).
    """
    if not prefix:
        raise ValueError('prefix must be non-empty to prevent accidental wipe')

    entities = client.list_entities()
    matches = matching_entities(entities, prefix, include_records=include_records)

    summary = {'teams': 0, 'roles': 0, 'nodes': 0,
                'records': 0, 'shared_folders': 0, 'errors': 0}

    # Records first — they can reference enterprise nodes/teams/roles
    # via share metadata; deleting the record cleanly before the
    # structure avoids orphaned share edges.
    if include_records:
        for rec in matches.get('records', []):
            uid = rec.get('uid') or rec.get('record_uid') or ''
            title = rec.get('title') or rec.get('name') or uid
            if not uid:
                continue
            call_ok = client.delete_record(uid)
            leftover = (not dry_run) and _still_present(client, 'records', 'uid', uid)
            if call_ok and not leftover:
                summary['records'] += 1
                logging.info('deleted record: %s (%s)', title, uid)
            else:
                summary['errors'] += 1
                detail = ('silent no-op (still present)' if call_ok and leftover
                          else 'call failed')
                logging.warning('record delete %s: %s (%s)',
                                detail, title, uid)

    # Shared folders next — after records (records may live inside an
    # SF; deleting the SF first cascades records out, which is fine
    # but doesn't help the record loop) and before teams (an SF's
    # team grants survive SF deletion as orphaned references that
    # confuse subsequent enumerations). Bug 25 — earlier cleanup
    # missed SFs entirely, so structure-restore SFs survived
    # cross-run and Bug 22 fresh-defaults validation needed manual
    # rmdir. Always-on once the client enumerates them.
    for sf in matches.get('shared_folders', []):
        uid = sf.get('uid') or sf.get('shared_folder_uid') or ''
        name = sf.get('name', '') or uid
        if not uid:
            continue
        call_ok = client.delete_shared_folder(uid)
        leftover = (not dry_run) and _still_present(client, 'shared_folders', 'uid', uid)
        if call_ok and not leftover:
            summary['shared_folders'] += 1
            logging.info('deleted shared_folder: %s (%s)', name, uid)
        else:
            summary['errors'] += 1
            detail = ('silent no-op (still present)' if call_ok and leftover
                      else 'call failed')
            logging.warning('shared_folder delete %s: %s (%s)',
                            detail, name, uid)

    for team in matches['teams']:
        name = team.get('name', '')
        if not name:
            continue
        call_ok = client.delete_team(name)
        leftover = (not dry_run) and _still_present(client, 'teams', 'name', name)
        if call_ok and not leftover:
            summary['teams'] += 1
            logging.info('deleted team: %s', name)
        else:
            summary['errors'] += 1
            detail = ('silent no-op (still present)' if call_ok and leftover
                      else 'call failed')
            logging.warning('team delete %s: %s', detail, name)

    for role in matches['roles']:
        name = role.get('name', '')
        if not name:
            continue
        call_ok = client.delete_role(name)
        leftover = (not dry_run) and _still_present(client, 'roles', 'name', name)
        if call_ok and not leftover:
            summary['roles'] += 1
            logging.info('deleted role: %s', name)
        else:
            summary['errors'] += 1
            detail = ('silent no-op (still present)' if call_ok and leftover
                      else 'call failed')
            logging.warning('role delete %s: %s', detail, name)

    # Nodes: sort by true depth (walk parent chain) descending — so
    # grandchildren are deleted before their parents.
    #
    # Discovered live 2026-04-19 during Tier 6 rehearsal: both
    # MIGTEST-Child-Node (parent='MIGRATION-TEST-NODE') and
    # MIGTEST-Grandchild-Node (parent='MIGTEST-Child-Node') had 0
    # backslashes in their parent strings, so the old
    # `parent.count('\\')` heuristic returned 0 for both, producing
    # undefined delete order. Child got attempted first, Commander
    # silently warned 'You must first delete or move the objects on
    # this node', and the node survived. Combined with the silent
    # no-op fix below, this correctly walks the parent chain using
    # the nodes in scope so depth is real and sorting is stable.
    parent_by_name = {
        (n.get('name') or ''): (n.get('parent') or n.get('parent_node') or '')
        for n in matches['nodes']
    }

    def node_depth(n):
        """True depth of a node, preferring in-scope parent-chain walk.

        If a node's parent is itself being deleted, walk the chain to
        count how deep it is. Otherwise, fall back to the backslash
        count of the parent path — that's Commander's own encoding
        for enterprise-info projections and gives a stable order when
        the parent chain is outside the deletion scope.
        """
        parent = n.get('parent') or n.get('parent_node') or ''
        seen = set()
        depth = 0
        current = parent
        while current and current in parent_by_name and current not in seen:
            seen.add(current)
            depth += 1
            current = parent_by_name.get(current, '')
        if depth == 0:
            # Parent isn't being deleted; fall back to backslash-depth.
            depth = parent.count('\\')
        return depth

    for node in sorted(matches['nodes'], key=node_depth, reverse=True):
        name = node.get('name', '')
        if not name:
            continue
        call_ok = client.delete_node(name)
        leftover = (not dry_run) and _still_present(client, 'nodes', 'name', name)
        if call_ok and not leftover:
            summary['nodes'] += 1
            logging.info('deleted node: %s', name)
        else:
            summary['errors'] += 1
            detail = ('silent no-op (still present)' if call_ok and leftover
                      else 'call failed')
            logging.warning('node delete %s: %s', detail, name)

    return summary
