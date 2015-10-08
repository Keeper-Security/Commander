import pymysql.cursors

class MySQL:
    """Commander Plugin for MySQL Database Server"""
    def __init__(self, host='', port=3306, 
                 pem_file='', user='', password='', db=''):
        self.host = host
        self.port = port
        self.pem_file = pem_file
        self.user = user
        self.password = password
        self.db = db

    def login():
        connection = pymysql.connect(host, user, password, db, 'utf8mb4', cursorclass=pymysql.cursors.DictCursor)

    def logout():
        return

    def rotate():
        return

