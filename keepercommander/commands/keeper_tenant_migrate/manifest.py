"""Build a source_uid,target_uid manifest by matching record titles.

After `records-export → convert → records-import`, you have:
  - source export dir: one file per source record (filename = source UID;
    file contents include title)
  - target session: all imported records with the same titles but
    freshly-minted target UIDs

This module's single job: scan both sides, pair records by title, and
emit a CSV that `records-attachments` and `records-shares` consume.

Ambiguous matches (same title appears multiple times on either side)
are flagged, not silently resolved. Caller decides whether to use
--allow-ambiguous to pick first-match, or disambiguate manually.
"""

import csv
import json
import logging
import os
from collections import defaultdict


def load_source_uid_by_title(source_dir):
    """Scan the export dir. Returns {title: [source_uid]} (list for collisions)."""
    titles = defaultdict(list)
    if not os.path.isdir(source_dir):
        return dict(titles)
    for fn in sorted(os.listdir(source_dir)):
        if not fn.endswith('.json'):
            continue
        path = os.path.join(source_dir, fn)
        try:
            with open(path) as f:
                rec = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        title = (rec.get('title') or '').strip()
        uid = (rec.get('record_uid') or os.path.splitext(fn)[0]).strip()
        if title and uid:
            titles[title].append(uid)
    return dict(titles)


def load_target_uid_by_title(record_cache, get_record):
    """Walk params.record_cache, returns {title: [target_uid]}."""
    titles = defaultdict(list)
    for uid in record_cache.keys() if hasattr(record_cache, 'keys') else []:
        rec = get_record(uid)
        if rec is None:
            continue
        title = (getattr(rec, 'title', '') or '').strip()
        if title:
            titles[title].append(uid)
    return dict(titles)


def pair_by_title(source_titles, target_titles, *, allow_ambiguous=False):
    """Return (pairs, ambiguous, source_only, target_only).

    pairs:        list of {source_uid, target_uid, title}
    ambiguous:    list of {title, source_uids, target_uids} (not paired)
    source_only:  titles present only on source
    target_only:  titles present only on target
    """
    pairs = []
    ambiguous = []
    source_only = []
    target_only = []

    for title, src_uids in source_titles.items():
        tgt_uids = target_titles.get(title, [])
        if not tgt_uids:
            source_only.append(title)
            continue
        if len(src_uids) == 1 and len(tgt_uids) == 1:
            pairs.append({
                'source_uid': src_uids[0],
                'target_uid': tgt_uids[0],
                'title': title,
            })
        elif allow_ambiguous:
            # Pair positionally: first source with first target, etc.
            for i in range(min(len(src_uids), len(tgt_uids))):
                pairs.append({
                    'source_uid': src_uids[i],
                    'target_uid': tgt_uids[i],
                    'title': title,
                })
            if len(src_uids) != len(tgt_uids):
                ambiguous.append({
                    'title': title,
                    'source_uids': src_uids,
                    'target_uids': tgt_uids,
                })
        else:
            ambiguous.append({
                'title': title,
                'source_uids': src_uids,
                'target_uids': tgt_uids,
            })

    for title in target_titles:
        if title not in source_titles:
            target_only.append(title)

    return pairs, ambiguous, source_only, target_only


def write_manifest_csv(pairs, output_path):
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['source_uid', 'target_uid', 'title'])
        writer.writeheader()
        for p in pairs:
            writer.writerow(p)
    logging.info('Wrote %d pair(s) to %s', len(pairs), output_path)

    # SHA-256 sidecar — closes red-team Scenario 02 ('manifest.csv tamper
    # between keeper-migrate and downstream import') structurally. The
    # sidecar is a single line in `sha256sum -c` format so any consumer
    # (declarative SDK import path, operator running
    # `sha256sum -c manifest.csv.sha256`) can verify integrity from the
    # moment manifest.csv exists, not just after `verify` runs later.
    # OUTPUT_CONTRACT.md v1.1+ documents this artifact.
    try:
        from .audit import sha256_of_file
        digest = sha256_of_file(output_path)
        sidecar_path = output_path + '.sha256'
        sidecar_basename = os.path.basename(output_path)
        with open(sidecar_path, 'w') as f:
            # GNU coreutils `sha256sum -c` format: '<hex>  <filename>'
            # (two spaces). Filename is BASENAME not absolute — so the
            # sidecar can verify when run from the parent directory.
            f.write(f'{digest}  {sidecar_basename}\n')
        os.chmod(sidecar_path, 0o600)
    except OSError as _e:
        logging.warning(
            'manifest.csv sha256 sidecar emit skipped (I/O error): %s', _e
        )


def build_from_session(source_dir, params, output_path, *, allow_ambiguous=False):
    """Entry point used by the records-manifest subcommand.

    Returns {pairs, ambiguous, source_only, target_only} counts + lists.
    """
    from keepercommander import api
    source_titles = load_source_uid_by_title(source_dir)
    target_titles = load_target_uid_by_title(
        getattr(params, 'record_cache', {}) or {},
        lambda uid: api.get_record(params, uid),
    )
    pairs, amb, src_only, tgt_only = pair_by_title(
        source_titles, target_titles, allow_ambiguous=allow_ambiguous,
    )
    write_manifest_csv(pairs, output_path)
    return {
        'pairs': pairs,
        'ambiguous': amb,
        'source_only': src_only,
        'target_only': tgt_only,
        'counts': {'pairs': len(pairs), 'ambiguous': len(amb),
                   'source_only': len(src_only), 'target_only': len(tgt_only)},
    }
