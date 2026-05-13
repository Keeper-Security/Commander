"""Node path remapping utilities.

Every Keeper source path like `My company\\Subsidiary\\Team` must be translated
for the target tenant. Three primitives cover every bash-port callsite:

    leaf_of("My company\\A\\B")     -> "B"
    remap_root("My company\\A", "My company", "Keeperdemo")
                                    -> "Keeperdemo\\A"
    remap_node(src, source_root, target_root)
                                    -> target-side name for Commander's --node flag

`remap_node` returns the LEAF name (not the full path) because Commander's
--node flag only accepts a leaf name when the target has an ambiguous or
renamed root. This matches what proved to work end-to-end against MSP.
"""

SEP = '\\'


def leaf_of(path):
    """Return the last segment of a backslash-separated path."""
    if not path:
        return path
    return path.rsplit(SEP, 1)[-1] or path


def parent_of(path):
    """Return the path up to but not including the last segment."""
    if not path or SEP not in path:
        return ''
    return path.rsplit(SEP, 1)[0]


def split_path(path):
    """Return the path as a list of segments."""
    if not path:
        return []
    return path.split(SEP)


def join_path(segments):
    """Inverse of split_path."""
    return SEP.join(s for s in segments if s)


def remap_root(src_path, source_root, target_root):
    """Replace the top-level root segment in src_path with target_root.

    Used when the full remapped path is needed (e.g. for lookups in target
    enterprise data). For Commander CLI --node arguments, use remap_node().
    """
    if not src_path:
        return src_path
    if not source_root or not target_root:
        return src_path
    if src_path == source_root:
        return target_root
    prefix = source_root + SEP
    if src_path.startswith(prefix):
        return target_root + SEP + src_path[len(prefix):]
    return src_path


def remap_node(src_path, source_root='', target_root=''):
    """Return the node identifier safe to pass to Commander's --node.

    - Empty source → unchanged.
    - Source equals source_root → return target_root (or leaf of it).
    - Everything else → leaf name, which is unambiguous under a scoped
      subtree and avoids escape quoting nightmares with backslash paths.
    """
    if not src_path:
        return src_path
    if source_root and src_path == source_root:
        return target_root or src_path
    return leaf_of(src_path)
