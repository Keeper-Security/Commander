class Record:
    """Defines a Keeper Record"""

    def __init__(self,record_uid='',folder='',title='',login='',password='',
                 link='',notes='',custom_fields=[]):
        self.record_uid = record_uid 
        self.folder = folder 
        self.title = title 
        self.login = login 
        self.password = password 
        self.link = link 
        self.notes = notes 
        self.custom_fields = custom_fields 

