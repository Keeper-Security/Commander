import csv
import json
import logging
import os
import sys
import zipfile

from typing import Dict, List, Tuple

ATTACHMENT_FOLDER = 'Attachments'
CSV_FILENAME = 'secrets.csv'
column_B_index = 1
ZIP_FILENAME = 'keeper-archive.zip'
KEEPER_IMPORT = 'keeper-import.json'


logging.basicConfig(level=logging.INFO, format='%(message)s')

# load attachments files
attachment_files = {}    # type: Dict[str, str]
for folder_name, _, file_names in os.walk(ATTACHMENT_FOLDER):
    for file_name in file_names:
        full_path = os.path.join(folder_name, file_name)
        if file_name in attachment_files:
            logging.infols ('Filename at "%s" is not unique. Skipping', full_path)
        else:
            attachment_files[file_name] = full_path

if len(attachment_files) == 0:
    logging.error('No attachment files were loaded from %s. Exiting', ATTACHMENT_FOLDER)
    sys.exit(-1)

logging.info('Loaded %d attachments from %s', len(attachment_files), ATTACHMENT_FOLDER)

# load attachment.csv
CSV_FILENAME = 'secrets.csv'
secrets = []  # type: List[Tuple[str, int]]
with open(CSV_FILENAME, "r", encoding='utf-8-sig') as csvfile:
    reader = csv.reader(csvfile)
    next(csvfile)      # skip header row
    for row in reader:
        if row and len(row) >= column_B_index + 4:
            record_title = row[column_B_index]
            secret_id = row[column_B_index + 2]
            if not secret_id.isnumeric():
                logging.warning('CSV: record "%s" secret id is not integer', record_title)
                continue
            secrets.append((record_title, int(secret_id)))

if len(secrets) == 0:
    logging.error('No secrets were loaded from %s. Exiting', CSV_FILENAME)
    sys.exit(-1)

logging.info('Loaded %d secrets from %s', len(secrets), CSV_FILENAME)

# load export.json
with open(KEEPER_IMPORT, 'r', encoding='utf-8-sig') as jsonfile:
    import_json = json.load(jsonfile)
if 'records' not in import_json:
    logging.error('No record found in im,port file %s. Exiting', 'keeper-import.json')
    sys.exit(-1)

logging.info('Loaded %d records from %s', len(import_json['records']), 'keeper-import.json')

# secret lookup
duplicate_titles = set()
secret_id_lookup = {x[1]: x[0] for x in secrets}    # type: Dict[int, str]
record_title_lookup = {}     # type: Dict[str, dict]
for record in import_json['records']:
    title = record.get('title')
    if not title:
        logging.warning('Import record has no title. Skipping')
        continue
    title = title.casefold()
    if title in duplicate_titles:
        continue
    if title in record_title_lookup:
        duplicate_titles.add(title)
        del record_title_lookup[title]
        continue
    record_title_lookup[title] = record

skipped_attachments = []
# create zip archive
with zipfile.ZipFile(ZIP_FILENAME, mode='w', compresslevel=zipfile.ZIP_DEFLATED) as zf:
    for attachment in attachment_files:
        full_path = attachment_files[attachment]
        comps = attachment.split('_')
        if len(comps) < 3:
            skipped_attachments.append(full_path)
            logging.warning('Attachment file "%s" has invalid file name. Expected <SECRET_ID>_<FOLDER_ID>_<NAME>.<EXT>', full_path)
            continue

        if not comps[1].isnumeric():
            skipped_attachments.append(full_path)
            logging.warning('Attachment file "%s" has invalid file name. <SECRET_ID> component has to be numeric', full_path)
            continue
        secret_id = int(comps[1])
        if secret_id not in secret_id_lookup:
            skipped_attachments.append(full_path)
            logging.warning('Secret ID [%d] does not exist in %s', secret_id, CSV_FILENAME)
            continue

        title = secret_id_lookup[secret_id].casefold()
        if title in duplicate_titles:
            skipped_attachments.append(full_path)
            continue
        if title not in record_title_lookup:
            skipped_attachments.append(full_path)
            logging.warning('Cannot file record with title "%s"', secret_id_lookup[secret_id])
            continue
        record = record_title_lookup[title]
        if 'attachments' not in record:
            record['attachments'] = []
        if os.path.isfile(full_path):
            zf.write(full_path, f'files/{attachment}')
            record['attachments'].append({
                'file_uid': attachment
            })
        else:
            skipped_attachments.append(full_path)
            logging.warning('Attachment file "%s" cannot be found', full_path)

    f = json.dumps(import_json, indent=2, ensure_ascii=False)
    zf.writestr('export.json', f)

if len(duplicate_titles) > 0:
    logging.warning('\nSecret Duplicates')
    no = 1
    for title in duplicate_titles:
        logging.warning(f'{no:>5} : {title}')
        no += 1

if len(skipped_attachments) > 0:
    logging.warning('\nSkipped attachments')
    no = 1
    for attachment in skipped_attachments:
        logging.warning(f'{no:>5} : {attachment}')
        no += 1

