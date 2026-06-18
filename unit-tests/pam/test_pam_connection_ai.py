import pytest
from unittest.mock import patch

from keepercommander.commands.pam_import.keeper_ai_settings import (
    apply_ai_setting_changes,
    dedupe_ai_cli_option_specs,
    empty_keeper_ai_settings_dict,
    is_default_keeper_ai_settings,
    parse_ai_setting_spec,
)


class _Params:
    account_uid_bytes = b'\x01\x02\x03'
    user = 'user@example.com'


def test_dedupe_ai_cli_option_specs_reports_counts():
    specs, warnings = dedupe_ai_cli_option_specs(
        ['critical.allow=chmod', 'high.allow=wget', 'critical.allow=chmod', 'critical.allow=chmod'],
        '--set/-s',
    )
    assert specs == ['critical.allow=chmod', 'high.allow=wget']
    assert warnings == ['duplicate --set/-s ignored: critical.allow=chmod (3x)']


def test_dedupe_ai_cli_option_specs_no_warnings_when_unique():
    specs, warnings = dedupe_ai_cli_option_specs(['low'], '--unset/-u')
    assert specs == ['low']
    assert warnings == []


def test_is_default_keeper_ai_settings():
    assert is_default_keeper_ai_settings(None)
    assert is_default_keeper_ai_settings({})
    assert is_default_keeper_ai_settings(empty_keeper_ai_settings_dict())
    assert not is_default_keeper_ai_settings({
        'version': 'v1.0.0',
        'riskLevels': {'high': {'aiSessionTerminate': True}},
    })


def test_remove_resource_keeper_ai_settings_emits_deletion():
    params = _Params()
    captured = {}

    def _capture(_params, _resource_uid, _config_uid, _record_key, dag_path):
        captured['dag_path'] = dag_path
        return True

    from keepercommander.commands.pam_import import keeper_ai_settings as ai_mod
    with patch.object(ai_mod, '_resolve_resource_settings_inputs', return_value=(b'key', 'config')), \
         patch.object(ai_mod, '_delete_resource_data_edge_legacy', side_effect=_capture):
        result = ai_mod.remove_resource_keeper_ai_settings(params, 'resource', 'config')
    assert result is True
    assert captured['dag_path'] == 'ai_settings'


def test_remove_resource_keeper_ai_settings_already_absent():
    params = _Params()

    from keepercommander.commands.pam_import import keeper_ai_settings as ai_mod
    with patch.object(ai_mod, '_resolve_resource_settings_inputs', return_value=(b'key', 'config')), \
         patch.object(ai_mod, '_delete_resource_data_edge_legacy', return_value=None):
        result = ai_mod.remove_resource_keeper_ai_settings(params, 'resource', 'config')
    assert result is None


def test_parse_ai_setting_spec_set():
    assert parse_ai_setting_spec('low.terminate=false') == ('low', 'terminate', 'false')
    assert parse_ai_setting_spec('high.allow=chmod') == ('high', 'allow', 'chmod')
    assert parse_ai_setting_spec('critical.deny=kill -9') == ('critical', 'deny', 'kill -9')


def test_parse_ai_setting_spec_unset():
    assert parse_ai_setting_spec('low') == ('low', None, None)
    assert parse_ai_setting_spec('medium.allow') == ('medium', 'allow', None)
    assert parse_ai_setting_spec('high.deny=wget') == ('high', 'deny', 'wget')


def test_parse_ai_setting_spec_rejects_low_deny():
    with pytest.raises(ValueError, match='deny is not supported'):
        parse_ai_setting_spec('low.deny=bash')


def test_parse_ai_setting_spec_missing_value_suggests_unset():
    with pytest.raises(ValueError, match='--unset\\|-u'):
        parse_ai_setting_spec('high.terminate=')


def test_apply_ai_setting_changes_merge_without_default_low_stub():
    params = _Params()
    result, warnings = apply_ai_setting_changes(None, ['high.allow=chmod'], None, params)

    assert warnings == []
    assert result['version'] == 'v1.0.0'
    assert result['riskLevels']['high']['tags']['allow'][0]['tag'] == 'chmod'
    assert 'low' not in result['riskLevels']


def test_apply_ai_setting_changes_tag_upsert_no_duplicate():
    params = _Params()
    existing = {
        'version': 'v1.0.0',
        'riskLevels': {
            'high': {
                'tags': {'allow': [{'tag': 'chmod', 'auditLog': [{'action': 'added_to_allow'}]}]},
            },
        },
    }

    result, warnings = apply_ai_setting_changes(existing, ['high.allow=chmod'], None, params)

    assert warnings == []
    assert len(result['riskLevels']['high']['tags']['allow']) == 1


def test_apply_ai_setting_changes_unset_level_and_tag():
    params = _Params()
    existing = {
        'version': 'v1.0.0',
        'riskLevels': {
            'critical': {
                'aiSessionTerminate': True,
                'tags': {'allow': [{'tag': 'mount', 'auditLog': []}]},
            },
            'low': {
                'aiSessionTerminate': False,
                'tags': {'allow': [{'tag': 'chmod', 'auditLog': []}, {'tag': 'wget', 'auditLog': []}]},
            },
        },
    }

    result, warnings = apply_ai_setting_changes(existing, None, ['critical', 'low.allow=chmod'], params)

    assert warnings == []
    assert 'critical' not in result['riskLevels']
    low_allow = [t['tag'] for t in result['riskLevels']['low']['tags']['allow']]
    assert low_allow == ['wget']
    assert result['riskLevels']['low']['aiSessionTerminate'] is False


def test_apply_ai_setting_changes_set_terminate_rejects_invalid_value():
    params = _Params()
    with pytest.raises(ValueError, match='invalid terminate value "truez"'):
        apply_ai_setting_changes(None, ['high.terminate=truez'], None, params)


def test_apply_ai_setting_changes_set_terminate_accepts_true_false_only():
    params = _Params()
    result_true, _ = apply_ai_setting_changes(None, ['high.terminate=true'], None, params)
    assert result_true['riskLevels']['high']['aiSessionTerminate'] is True

    result_false, _ = apply_ai_setting_changes(result_true, ['medium.terminate=FALSE'], None, params)
    assert result_false['riskLevels']['medium']['aiSessionTerminate'] is False


def test_apply_ai_setting_changes_set_terminate():
    params = _Params()
    result, warnings = apply_ai_setting_changes(None, ['medium.terminate=true'], None, params)
    assert warnings == []
    assert result['riskLevels']['medium']['aiSessionTerminate'] is True


def test_apply_ai_setting_changes_low_terminate_true_warns_and_stays_false():
    params = _Params()
    result, warnings = apply_ai_setting_changes(None, ['low.terminate=true'], None, params)

    assert warnings == ['risk level low.terminate always defaults to false.']
    assert result == {}


def test_apply_ai_setting_changes_low_terminate_false_is_noop_when_empty():
    params = _Params()
    result, warnings = apply_ai_setting_changes(None, ['low.terminate=false'], None, params)

    assert warnings == []
    assert result == {}
    assert is_default_keeper_ai_settings(None)


def test_apply_ai_setting_changes_paired_unset_set_tag_preserves_audit_log():
    params = _Params()
    original_audit = [{'date': 1, 'userId': 'u1', 'action': 'added_to_allow'}]
    existing = {
        'version': 'v1.0.0',
        'riskLevels': {
            'high': {
                'tags': {'allow': [{'tag': 'chmod', 'auditLog': original_audit}]},
            },
        },
    }

    result, warnings = apply_ai_setting_changes(
        existing,
        ['high.allow=chmod'],
        ['high.allow=chmod'],
        params,
    )

    assert warnings == ['--set/-s overrides --unset/-u: high.allow=chmod']
    entry = result['riskLevels']['high']['tags']['allow'][0]
    assert entry['tag'] == 'chmod'
    assert entry['auditLog'] == original_audit


def test_apply_ai_setting_changes_paired_unset_set_terminate_noop_when_already_true():
    params = _Params()
    existing = {
        'version': 'v1.0.0',
        'riskLevels': {
            'high': {'aiSessionTerminate': True},
        },
    }

    result, warnings = apply_ai_setting_changes(
        existing,
        ['high.terminate=true'],
        ['high.terminate'],
        params,
    )

    assert warnings == []
    assert result['riskLevels']['high']['aiSessionTerminate'] is True


def test_apply_ai_setting_changes_mirrored_unset_set_different_tag_values_warns():
    params = _Params()
    result, warnings = apply_ai_setting_changes(
        None,
        ['critical.allow=chmod'],
        ['critical.allow=chmo'],
        params,
    )

    assert warnings == [
        '--set/-s overrides --unset/-u: critical.allow=chmo (mirrors -s critical.allow=chmod)',
    ]
    assert result['riskLevels']['critical']['tags']['allow'][0]['tag'] == 'chmod'


def test_apply_ai_setting_changes_partial_unset_not_mirrored_with_set():
    params = _Params()
    existing = {
        'version': 'v1.0.0',
        'riskLevels': {
            'critical': {
                'tags': {'allow': [{'tag': 'wget', 'auditLog': []}]},
            },
        },
    }
    result, warnings = apply_ai_setting_changes(
        existing,
        ['critical.allow=chmod'],
        ['critical.allow'],
        params,
    )

    assert warnings == []
    tags = [t['tag'] for t in result['riskLevels']['critical']['tags']['allow']]
    assert tags == ['chmod']


def test_apply_ai_setting_changes_unset_all_leaves_empty():
    params = _Params()
    existing = {
        'version': 'v1.0.0',
        'riskLevels': {
            'low': {
                'aiSessionTerminate': False,
                'tags': {'allow': [{'tag': 'chmod', 'auditLog': []}]},
            },
        },
    }

    result, warnings = apply_ai_setting_changes(existing, None, ['low'], params)

    assert warnings == []
    assert result == {}


def test_pam_connection_ai_resource_types_include_rbi():
    from keepercommander.commands.tunnel_and_connections import _PAM_CONNECTION_AI_RESOURCE_TYPES

    assert 'pamRemoteBrowser' in _PAM_CONNECTION_AI_RESOURCE_TYPES
    assert 'pamMachine' in _PAM_CONNECTION_AI_RESOURCE_TYPES
    assert 'pamDatabase' in _PAM_CONNECTION_AI_RESOURCE_TYPES
    assert 'pamDirectory' in _PAM_CONNECTION_AI_RESOURCE_TYPES
