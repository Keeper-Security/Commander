import unittest

from keepercommander.commands.keeper_tenant_migrate.helpers.node_paths import (
    join_path,
    leaf_of,
    parent_of,
    remap_node,
    remap_root,
    split_path,
)


class LeafOfTests(unittest.TestCase):
    def test_single_segment_returns_self(self):
        self.assertEqual(leaf_of('My company'), 'My company')

    def test_multi_segment_returns_last(self):
        self.assertEqual(leaf_of('My company\\A\\B'), 'B')

    def test_trailing_sep_returns_path(self):
        # rsplit yields '' as last segment; fall back to input (legacy behavior).
        self.assertEqual(leaf_of('My company\\A\\'), 'My company\\A\\')

    def test_empty_input(self):
        self.assertEqual(leaf_of(''), '')
        self.assertIsNone(leaf_of(None))


class ParentOfTests(unittest.TestCase):
    def test_returns_everything_above_leaf(self):
        self.assertEqual(parent_of('Root\\Child\\Grand'), 'Root\\Child')

    def test_no_separator_returns_empty(self):
        self.assertEqual(parent_of('Only'), '')

    def test_empty_input(self):
        self.assertEqual(parent_of(''), '')


class SplitJoinTests(unittest.TestCase):
    def test_roundtrip(self):
        self.assertEqual(join_path(split_path('Root\\A\\B')), 'Root\\A\\B')

    def test_empty_segments_filtered_on_join(self):
        self.assertEqual(join_path(['Root', '', 'A']), 'Root\\A')


class RemapRootTests(unittest.TestCase):
    def test_swaps_only_top_segment(self):
        self.assertEqual(
            remap_root('My company\\Dept\\Team', 'My company', 'Keeperdemo'),
            'Keeperdemo\\Dept\\Team',
        )

    def test_root_itself_becomes_target_root(self):
        self.assertEqual(remap_root('My company', 'My company', 'Keeperdemo'), 'Keeperdemo')

    def test_unrelated_prefix_unchanged(self):
        self.assertEqual(
            remap_root('Orphan\\Dept', 'My company', 'Keeperdemo'),
            'Orphan\\Dept',
        )

    def test_noop_when_roots_missing(self):
        self.assertEqual(remap_root('Root\\A', '', 'Keeperdemo'), 'Root\\A')
        self.assertEqual(remap_root('Root\\A', 'Root', ''), 'Root\\A')

    def test_substring_match_not_triggered_without_separator(self):
        # 'My companyX' does not start with 'My company\'
        self.assertEqual(
            remap_root('My companyX\\A', 'My company', 'Keeperdemo'),
            'My companyX\\A',
        )


class RemapNodeTests(unittest.TestCase):
    def test_leaf_extracted_for_commander_node_flag(self):
        self.assertEqual(
            remap_node('My company\\Subsidiary\\Team'),
            'Team',
        )

    def test_source_root_maps_to_target_root(self):
        self.assertEqual(
            remap_node('My company', source_root='My company', target_root='Keeperdemo'),
            'Keeperdemo',
        )

    def test_empty_input_returned_unchanged(self):
        self.assertEqual(remap_node(''), '')
        self.assertIsNone(remap_node(None))

    def test_leaf_of_single_segment_is_itself(self):
        self.assertEqual(remap_node('OnlyNode'), 'OnlyNode')


if __name__ == '__main__':
    unittest.main()
