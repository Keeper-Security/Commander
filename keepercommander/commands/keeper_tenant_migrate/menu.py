"""Dependency-free menu primitives for the wizard.

No external deps (no questionary / inquirer) — plain stdin/stdout. Each
primitive accepts injectable `input_fn` and `output_fn` so tests drive
them without a TTY.

Primitives
----------

  single_select(title, options) -> int | None
      Number-keyed list; returns 0-based index or None on cancel.

  multi_toggle(title, options, preselected=...) -> list[int]
      Numbered toggle; each number flips a selection. Blank input
      (just Enter) confirms. Returns the selected indices.

  prompt_text(title, default='', validate=None) -> str | None
      Plain text input with optional validator callback + default.

  prompt_choice(title, choices) -> str | None
      Shorthand: show a one-line '[1=A / 2=B / 3=C]' prompt and return
      the matched choice string.

All primitives return `None` on EOF or KeyboardInterrupt, so the caller
can treat a cancel uniformly.
"""


class MenuCancelled(Exception):
    """User hit Ctrl+C or EOF — propagate upward so the wizard exits cleanly."""


def _default_in(prompt):
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        raise MenuCancelled from None


def _default_out(line):
    print(line, flush=True)


def _divider(width=62):
    return '━' * width


def single_select(title, options, *, input_fn=None, output_fn=None,
                  allow_cancel=True):
    """Numbered menu. Returns the 0-based index of the chosen option or
    None when the user cancels (q / empty)."""
    in_ = input_fn or _default_in
    out = output_fn or _default_out

    out('')
    out(_divider())
    out(f'  {title}')
    out(_divider())
    for i, opt in enumerate(options, start=1):
        out(f'  {i:>2}) {opt}')
    if allow_cancel:
        out('   q) cancel')
    out('')

    for _ in range(5):
        try:
            raw = in_('  > ').strip().lower()
        except MenuCancelled:
            return None
        if allow_cancel and raw in ('q', 'quit', ''):
            return None
        try:
            idx = int(raw) - 1
        except ValueError:
            out(f'  not a number: {raw!r}')
            continue
        if 0 <= idx < len(options):
            return idx
        out(f'  out of range: {raw!r} (1-{len(options)})')
    return None


def multi_toggle(title, options, *, preselected=(), input_fn=None,
                 output_fn=None):
    """Numbered toggle list. Each numeric input flips that option's
    selection. Empty input (just Enter) confirms. Returns a sorted list
    of 0-based indices for the final selection. None on cancel."""
    in_ = input_fn or _default_in
    out = output_fn or _default_out

    selected = set(preselected or ())

    out('')
    out(_divider())
    out(f'  {title}')
    out(_divider())
    out('  (type a number to toggle; Enter to confirm; q to cancel)')

    while True:
        out('')
        for i, opt in enumerate(options, start=1):
            mark = 'x' if i - 1 in selected else ' '
            out(f'  [{mark}] {i:>2}) {opt}')
        try:
            raw = in_('  > ').strip().lower()
        except MenuCancelled:
            return None
        if raw in ('q', 'quit'):
            return None
        if raw == '':
            return sorted(selected)
        try:
            idx = int(raw) - 1
        except ValueError:
            out(f'  not a number: {raw!r}')
            continue
        if 0 <= idx < len(options):
            selected.symmetric_difference_update({idx})
        else:
            out(f'  out of range: {raw!r}')


def prompt_text(title, *, default='', validate=None, input_fn=None,
                output_fn=None):
    """Text prompt. `validate(s)` returns None if ok, else an error string.
    Returns the entered text (or `default` on empty), None on cancel."""
    in_ = input_fn or _default_in
    out = output_fn or _default_out

    out('')
    out(f'  {title}')
    hint = f' [{default}]' if default else ''
    for _ in range(5):
        try:
            raw = in_(f'  >{hint} ').strip()
        except MenuCancelled:
            return None
        value = raw or default
        if not value:
            out('  value required')
            continue
        if validate:
            err = validate(value)
            if err:
                out(f'  {err}')
                continue
        return value
    return None


def prompt_choice(title, choices, *, input_fn=None, output_fn=None,
                   default=None):
    """Shorthand: inline `[1=US, 2=EU, 3=AU, ...]` prompt. Returns the
    matching choice string (case-preserved), None on cancel."""
    in_ = input_fn or _default_in
    out = output_fn or _default_out

    labels = [f'{i + 1}={c}' for i, c in enumerate(choices)]
    out('')
    out(f'  {title}  [{", ".join(labels)}]')
    hint = f' default={default}' if default else ''
    for _ in range(5):
        try:
            raw = in_(f'  >{hint} ').strip()
        except MenuCancelled:
            return None
        if not raw and default:
            return default
        # Accept numeric index or the string itself
        for i, c in enumerate(choices):
            if raw == str(i + 1) or raw.lower() == c.lower():
                return c
        out(f'  not a valid choice: {raw!r}')
    return None


def prompt_yes_no(title, *, default_yes=False, input_fn=None,
                   output_fn=None):
    """Lightweight yes/no prompt — thinner wrapper than the safeguards
    module's `confirm_interactive` (which includes a banner). None on
    cancel, True/False otherwise."""
    in_ = input_fn or _default_in
    out = output_fn or _default_out

    hint = '[Y/n]' if default_yes else '[y/N]'
    try:
        raw = in_(f'  {title} {hint} ').strip().lower()
    except MenuCancelled:
        return None
    if not raw:
        return default_yes
    if raw in ('y', 'yes'):
        return True
    if raw in ('n', 'no'):
        return False
    out(f'  unrecognized: {raw!r}; defaulting to no')
    return False
