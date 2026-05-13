"""MSP → Managed-Company context switcher.

Commander's `switch-to-mc` does NOT mutate the caller's `params` object.
It stashes the MC-scoped params in a module-level dict
(`msp.mc_params_dict[current_mc_id]`) and expects Commander's
interactive shell (`cli.loop`) to swap the `params` reference before
each subsequent command via `msp.current_mc_id` / `msp.msp_params`.

Plugin subcommands don't run through that loop — they call `.execute()`
directly. If we just call `SwitchToMcCommand().execute(params, mc=...)`
and then invoke another subcommand with the SAME `params`, the second
call hits the MSP, not the MC. This is a silent no-op from the
operator's perspective: "Switched to MC X" shows in logs, but every
subsequent write lands on the MSP root. Discovered live 2026-04-19.

The fix: after switch-to-mc, read the MC's params from
`msp.mc_params_dict[current_mc_id]` and return THAT to the caller.
Callers receive the correct params via `MCContext.__enter__` return
value and must pass it (not the original) to subsequent subcommands.

Paired with `switch-to-msp` for the reset.
"""

import logging


def _mc_module():
    """Commander's msp module — encapsulates the globals we need."""
    from keepercommander.commands import msp
    return msp


def switch_to_mc(params, mc_name_or_id):
    """Invoke Commander's switch-to-mc command.

    Returns (ok: bool, mc_params) where mc_params is the MC-scoped
    KeeperParams to use for subsequent operations, or the original
    params when no switch occurred / switch failed.
    """
    if not mc_name_or_id:
        return True, params
    try:
        from keepercommander.commands.msp import SwitchToMcCommand
    except ImportError as e:
        logging.warning('switch-to-mc unavailable: %s', e)
        return False, params
    try:
        SwitchToMcCommand().execute(params, mc=str(mc_name_or_id))
    except Exception as e:                             # noqa: BLE001
        logging.warning('switch-to-mc(%r) failed: %r', mc_name_or_id, e)
        return False, params

    # Pull the MC-scoped params Commander stashed. If it isn't there
    # something went wrong server-side (the execute() would normally
    # raise) — bail out to the MSP params so the caller can decide.
    msp = _mc_module()
    mc_id = getattr(msp, 'current_mc_id', None)
    mc_params = msp.mc_params_dict.get(mc_id) if mc_id else None
    if mc_params is None:
        logging.warning('switch-to-mc(%r) reported success but no MC params '
                        'were stashed — treating as failed switch',
                        mc_name_or_id)
        return False, params

    logging.info('Switched context to MC: %s (id=%s)', mc_name_or_id, mc_id)
    return True, mc_params


def switch_to_msp(params):
    """Return to MSP-scope after an MC-scoped run.

    Returns (ok: bool, msp_params). `msp_params` is the original MSP-
    scoped KeeperParams Commander stashed when the MC switch happened;
    callers should use it for any subsequent MSP-scope operations.
    Falls back to the supplied `params` if the reset fails.
    """
    try:
        from keepercommander.commands.msp import SwitchToMspCommand
    except ImportError as e:
        logging.warning('switch-to-msp unavailable: %s', e)
        return False, params
    msp = _mc_module()
    stashed_msp = getattr(msp, 'msp_params', None)
    try:
        SwitchToMspCommand().execute(params)
    except Exception as e:                             # noqa: BLE001
        logging.warning('switch-to-msp failed: %r', e)
        return False, stashed_msp or params
    # After a clean switch-to-msp, msp.msp_params is reset to None by
    # Commander's shell loop. Our stashed copy from pre-switch is the
    # authoritative MSP params.
    return True, stashed_msp or params


class MCContext:
    """Context-manager: enter = switch-to-mc; exit = switch-to-msp.

    CRITICAL: the MC-scoped params are exposed via the `.params`
    attribute after __enter__. Callers MUST use `ctx.params` for every
    subsequent SDK call inside the block — the input params still
    points at the MSP session.

    Correct usage::

        with MCContext(input_params, mc_name) as ctx:
            cmd.execute(ctx.params, ...)       # MC-scoped
        # after the `with` block, ctx.params is restored to MSP
    """

    def __init__(self, params, mc_name_or_id):
        # `.params` starts at the MSP session. On __enter__ we swap it
        # for the MC-scoped params; on __exit__ we swap it back.
        self.params = params
        self._input_params = params
        self.mc = mc_name_or_id
        self._entered = False

    def __enter__(self):
        if not self.mc:
            return self
        ok, new_params = switch_to_mc(self._input_params, self.mc)
        if ok:
            self._entered = True
            self.params = new_params
        else:
            # Caller decides whether to proceed — self.params stays
            # as the MSP params so a well-written caller can notice
            # the no-op and abort.
            logging.error('MCContext: switch-to-mc(%r) failed — '
                          'subsequent operations will run against the '
                          'MSP session, NOT the MC.', self.mc)
        return self

    def __exit__(self, *_exc):
        if self._entered:
            ok, restored = switch_to_msp(self.params)
            self.params = restored if ok else self._input_params
        return False
