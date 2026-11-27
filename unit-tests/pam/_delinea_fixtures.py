"""Shared builders for the Delinea PAM import tests."""

from keepercommander.importer.thycotic.pam import build_pam_import


def items(**values):
    """Secret Server ``items`` list. ``private_key`` becomes slug ``private-key``."""
    return [{'slug': key.replace('_', '-'), 'itemValue': value} for key, value in values.items()]


def secret(secret_id, name, template_id=None, **extra):
    row = {'id': secret_id, 'name': name, 'items': extra.pop('items', [])}
    if template_id is not None:
        row['secretTemplateId'] = template_id
    row.update(extra)
    return row


def build(*secrets, folder='F', project='Delinea Migration'):
    """``build_pam_import`` over one folder holding ``secrets``."""
    return build_pam_import([{'folderName': folder, 'secrets': list(secrets)}], project)


def resources(document):
    return document['pam_data']['resources']


def by_title(document, title):
    return next(r for r in resources(document) if r['title'] == title)


def user_titles(resource):
    return [user['title'] for user in resource['users']]


def connection(resource):
    return resource['pam_settings']['connection']
