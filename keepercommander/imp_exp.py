from keepercommander import api

def export(params, filename):

    records = [api.get_record(params, record_uid) for record_uid in params.record_cache if params.meta_data_cache[record_uid]['owner']]

    records.sort(key=lambda x: ((x.folder if x.folder else ' ') + x.title).lower(), reverse=False)

    with open(filename, 'wt') as f:
        for record in records:
            f.write(record.to_tab_delimited() + '\n')
        print('{0} records exported to {1}'.format(len(records), filename))
