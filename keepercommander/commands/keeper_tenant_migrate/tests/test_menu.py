import builtins
import unittest
from unittest.mock import patch

from keepercommander.commands.keeper_tenant_migrate.menu import (
    MenuCancelled,
    multi_toggle,
    prompt_choice,
    prompt_text,
    prompt_yes_no,
    single_select,
)


def _driver(inputs):
    """Feed a list of strings as successive prompt responses."""
    it = iter(inputs)
    outputs = []
    return (
        lambda _prompt: next(it),
        outputs.append,
        outputs,
    )


class SingleSelectTests(unittest.TestCase):
    def test_returns_zero_based_index(self):
        in_, out, _ = _driver(['2'])
        idx = single_select('Pick', ['A', 'B', 'C'], input_fn=in_, output_fn=out)
        self.assertEqual(idx, 1)

    def test_q_cancels(self):
        in_, out, _ = _driver(['q'])
        self.assertIsNone(single_select('Pick', ['A'], input_fn=in_, output_fn=out))

    def test_empty_cancels(self):
        in_, out, _ = _driver([''])
        self.assertIsNone(single_select('Pick', ['A'], input_fn=in_, output_fn=out))

    def test_out_of_range_reprompts(self):
        in_, out, _ = _driver(['99', '1'])
        idx = single_select('Pick', ['A'], input_fn=in_, output_fn=out)
        self.assertEqual(idx, 0)


class MultiToggleTests(unittest.TestCase):
    def test_toggle_on_off_on(self):
        # Toggle 1 ON, 2 ON, 1 OFF, confirm
        in_, out, _ = _driver(['1', '2', '1', ''])
        sel = multi_toggle('Pick all', ['A', 'B', 'C'],
                            input_fn=in_, output_fn=out)
        self.assertEqual(sel, [1])   # only B remains

    def test_preselected_persists(self):
        in_, out, _ = _driver([''])   # just confirm
        sel = multi_toggle('Pick', ['A', 'B'],
                            preselected=[0], input_fn=in_, output_fn=out)
        self.assertEqual(sel, [0])

    def test_q_cancels(self):
        in_, out, _ = _driver(['q'])
        self.assertIsNone(multi_toggle('Pick', ['A'], input_fn=in_, output_fn=out))


class PromptTextTests(unittest.TestCase):
    def test_returns_entered_text(self):
        in_, out, _ = _driver(['alice@x'])
        self.assertEqual(
            prompt_text('Email', input_fn=in_, output_fn=out),
            'alice@x',
        )

    def test_default_used_on_empty(self):
        in_, out, _ = _driver([''])
        self.assertEqual(
            prompt_text('Email', default='admin@x',
                         input_fn=in_, output_fn=out),
            'admin@x',
        )

    def test_validator_reprompts_on_error(self):
        def is_email(s):
            return None if '@' in s else 'must contain @'
        in_, out, _ = _driver(['bad', 'ok@x'])
        result = prompt_text('Email', validate=is_email,
                              input_fn=in_, output_fn=out)
        self.assertEqual(result, 'ok@x')


class PromptChoiceTests(unittest.TestCase):
    def test_numeric(self):
        in_, out, _ = _driver(['2'])
        self.assertEqual(
            prompt_choice('Region', ['US', 'EU', 'AU'],
                           input_fn=in_, output_fn=out),
            'EU',
        )

    def test_string_match(self):
        in_, out, _ = _driver(['eu'])
        self.assertEqual(
            prompt_choice('Region', ['US', 'EU'],
                           input_fn=in_, output_fn=out),
            'EU',
        )

    def test_default_used_on_empty(self):
        in_, out, _ = _driver([''])
        self.assertEqual(
            prompt_choice('Region', ['US', 'EU'], default='US',
                           input_fn=in_, output_fn=out),
            'US',
        )


class PromptYesNoTests(unittest.TestCase):
    def test_y_is_true(self):
        in_, out, _ = _driver(['y'])
        self.assertTrue(prompt_yes_no('ok?', input_fn=in_, output_fn=out))

    def test_n_is_false(self):
        in_, out, _ = _driver(['n'])
        self.assertFalse(prompt_yes_no('ok?', input_fn=in_, output_fn=out))

    def test_default_yes_on_empty(self):
        in_, out, _ = _driver([''])
        self.assertTrue(
            prompt_yes_no('ok?', default_yes=True, input_fn=in_, output_fn=out),
        )


class DefaultIOTests(unittest.TestCase):
    """Cover the module-level _default_in / _default_out fallbacks used
    when input_fn/output_fn are not injected (production path)."""

    def test_default_in_raises_menu_cancelled_on_eof(self):
        """EOFError from input() must raise MenuCancelled."""
        with patch.object(builtins, 'input', side_effect=EOFError):
            in_ = lambda _p: None  # noqa: E731 — silence flake; not used
            outs = []
            # Hit the default path by NOT passing input_fn:
            self.assertIsNone(single_select('Pick', ['A'],
                                              output_fn=outs.append))

    def test_default_in_raises_menu_cancelled_on_keyboard_interrupt(self):
        """KeyboardInterrupt from input() must raise MenuCancelled."""
        with patch.object(builtins, 'input', side_effect=KeyboardInterrupt):
            outs = []
            self.assertIsNone(single_select('Pick', ['A'],
                                              output_fn=outs.append))

    def test_default_out_writes_to_stdout(self):
        """Default output_fn uses print() — exercise the fallback path."""
        with patch.object(builtins, 'input', return_value='1'):
            with patch.object(builtins, 'print') as mock_print:
                idx = single_select('Pick', ['Only'])
                self.assertEqual(idx, 0)
                self.assertTrue(mock_print.called)


class SingleSelectMissingPathTests(unittest.TestCase):
    def test_input_fn_raises_menu_cancelled(self):
        """An input_fn that raises MenuCancelled returns None."""
        def cancel(_p):
            raise MenuCancelled
        outs = []
        self.assertIsNone(
            single_select('Pick', ['A'], input_fn=cancel,
                           output_fn=outs.append))

    def test_non_numeric_reprompts(self):
        """ValueError on int() prints 'not a number' and reprompts."""
        in_, out, outs = _driver(['abc', '1'])
        idx = single_select('Pick', ['A'], input_fn=in_, output_fn=out)
        self.assertEqual(idx, 0)
        self.assertTrue(any('not a number' in o for o in outs))

    def test_returns_none_after_five_invalid(self):
        """Five invalid inputs in a row exhausts the loop → None."""
        in_, out, _ = _driver(['x', 'y', 'z', '0', '99'])
        idx = single_select('Pick', ['A'], input_fn=in_, output_fn=out)
        self.assertIsNone(idx)

    def test_no_cancel_disables_q_and_empty(self):
        """When allow_cancel=False, neither 'q' nor '' returns None — they
        re-prompt as invalid."""
        in_, out, outs = _driver(['', '1'])
        idx = single_select('Pick', ['A'], input_fn=in_, output_fn=out,
                             allow_cancel=False)
        self.assertEqual(idx, 0)


class MultiToggleMissingPathTests(unittest.TestCase):
    def test_input_fn_raises_menu_cancelled(self):
        def cancel(_p):
            raise MenuCancelled
        self.assertIsNone(multi_toggle('Pick', ['A'], input_fn=cancel,
                                         output_fn=lambda _s: None))

    def test_non_numeric_reprompts_then_confirms(self):
        in_, out, outs = _driver(['abc', '1', ''])
        sel = multi_toggle('Pick', ['A', 'B'], input_fn=in_, output_fn=out)
        self.assertEqual(sel, [0])
        self.assertTrue(any('not a number' in o for o in outs))

    def test_out_of_range_reprompts(self):
        in_, out, outs = _driver(['99', '1', ''])
        sel = multi_toggle('Pick', ['A'], input_fn=in_, output_fn=out)
        self.assertEqual(sel, [0])
        self.assertTrue(any('out of range' in o for o in outs))


class PromptTextMissingPathTests(unittest.TestCase):
    def test_menu_cancelled_returns_none(self):
        def cancel(_p):
            raise MenuCancelled
        self.assertIsNone(prompt_text('Email', input_fn=cancel,
                                        output_fn=lambda _s: None))

    def test_empty_with_no_default_reprompts(self):
        """No default + blank input → 'value required', then accepts text."""
        in_, out, outs = _driver(['', 'ok@x'])
        result = prompt_text('Email', input_fn=in_, output_fn=out)
        self.assertEqual(result, 'ok@x')
        self.assertTrue(any('value required' in o for o in outs))

    def test_returns_none_after_five_attempts(self):
        in_, out, _ = _driver(['', '', '', '', ''])
        self.assertIsNone(prompt_text('Email', input_fn=in_, output_fn=out))


class PromptChoiceMissingPathTests(unittest.TestCase):
    def test_menu_cancelled_returns_none(self):
        def cancel(_p):
            raise MenuCancelled
        self.assertIsNone(prompt_choice('Region', ['US', 'EU'],
                                          input_fn=cancel,
                                          output_fn=lambda _s: None))

    def test_invalid_choice_reprompts_then_returns_none(self):
        """5 invalid attempts → returns None."""
        in_, out, outs = _driver(['XX', 'YY', 'ZZ', '99', 'bad'])
        result = prompt_choice('Region', ['US', 'EU'],
                                input_fn=in_, output_fn=out)
        self.assertIsNone(result)
        self.assertTrue(any('not a valid choice' in o for o in outs))


class PromptYesNoMissingPathTests(unittest.TestCase):
    def test_menu_cancelled_returns_none(self):
        def cancel(_p):
            raise MenuCancelled
        self.assertIsNone(prompt_yes_no('ok?', input_fn=cancel,
                                          output_fn=lambda _s: None))

    def test_unrecognized_input_defaults_to_false(self):
        in_, out, outs = _driver(['maybe'])
        result = prompt_yes_no('ok?', input_fn=in_, output_fn=out)
        self.assertFalse(result)
        self.assertTrue(any('unrecognized' in o for o in outs))


if __name__ == '__main__':
    unittest.main()
