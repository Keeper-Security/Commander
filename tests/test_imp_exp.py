from keepercommander.imp_exp import parse_line


class TestImpExp:

    def test_parse_line(self):
        record = parse_line('folder\ttitle\tlogin\tpassword\tlink\tline1\\\\nline2\\\\nline3\tcf1\tcf1val\tcf2\tcf2val')
        assert record.folder == 'folder'
        assert record.title == 'title'
        assert record.login == 'login'
        assert record.password == 'password'
        assert record.link == 'link'
        assert record.notes == 'line1\nline2\nline3'
        assert record.custom_fields == [
             {'name':'cf1', 'value': 'cf1val', 'type': 'text'},
             {'name':'cf2', 'value': 'cf2val', 'type': 'text'}]
