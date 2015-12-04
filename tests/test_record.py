from keepercommander.record import Record


class TestRecord:

    def test_to_tab_delimited(self):
        record = Record()
        record.folder = 'folder'
        record.title = 'title'
        record.login = 'login'
        record.password = 'password'
        record.login_url = 'login_url'
        record.notes = 'line1\nline2\nline3'
        record.custom_fields = [
            {'name':'cf1', 'value': 'cf1val', 'type': 'text'},
            {'name':'cf2', 'value': 'cf2val', 'type': 'text'}]
        assert record.to_tab_delimited() == 'folder\ttitle\tlogin\tpassword\tlogin_url\tline1\\\\nline2\\\\nline3\tcf1\tcf1val\tcf2\tcf2val'