import MySQLdb as mdb
import sys
from Vulnerability import *

class DatabaseManager:

    def __init__(self):
        self.connection = None
        '''try :
            self.conn = mdb.connect("127.0.0.1", "root","", "textbook") 
        except mdb.Error, e:
            print "Error %d: %s" % (e.args[0],e.args[1])
            sys.exit(1)
        self.cursor = self.connection.cursor()'''

    def __del__(self):
        self.connection.close()
        self.cursor.close()

    def addVulnerability(self,vul):
        pass
        
      

