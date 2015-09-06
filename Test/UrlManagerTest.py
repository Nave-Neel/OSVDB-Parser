#Unittest module to test UrlManager class

import sys
sys.path.append('..\Src')

from UrlManager import *
import unittest


class TestUrlManager(unittest.TestCase):

    #Setup an instance of UrlManager 
    def setUp(self):
        self.urlmanager = UrlManager()

    #Test getList method of UrlManager class - should return a list of vulnerabilites
    #found on the search results page
    def test_getList(self):
        l = [92445,89684,89659,89878,81401,90453,76466,73954,71943,71936,71938,70588,90044,7128]
        l2 = self.urlmanager.getList('http://www.osvdb.org/search/search?search%5Bvuln_title%5D=&search%5Btext_type%5D=titles&search%5Bs_date%5D=&search%5Be_date%5D=May+13%2C+2009&search%5Brefid%5D=&search%5Breferencetypes%5D=&search%5Bvendors%5D=&search%5Bcvss_score_from%5D=&search%5Bcvss_score_to%5D=&search%5Bcvss_av%5D=L&search%5Bcvss_ac%5D=*&search%5Bcvss_a%5D=M&search%5Bcvss_ci%5D=*&search%5Bcvss_ii%5D=*&search%5Bcvss_ai%5D=*&location_local=1&kthx=search')
        count = 0
        for element in l:
            assert str(element) == str(l2[count])
            count+=1

    #Test getVulnerability method of UrlManager class - should return a vulenrability
    #object based on the vulnerability url page        
    def test_getVulnerability(self):
        v = Vulnerability(7128,'MySQL show database Database Name Exposure',719,'2002-01-01','MySQL contains a flaw that may lead to an unauthorized information disclosure.The issue is triggered when an attacker issues the &quot;show databases&quot; command. In multiuser environments, this may expose the names of every databaseresulting in a loss of confidentiality.','Local Access Required, Remote / Network Access','Information Disclosure','Loss of Confidentiality',None,'Exploit Public',None,'Concern','Upgrade to version 4.0.2 or higher, as it has been reported to fix this vulnerability. An upgrade is required as there are no known workarounds.','Unknown or Incomplete',None,None,None,None,None,None,None)
        boolean = self.urlmanager.getVulnerability(7128) == v
        assert boolean is True
        
    def tearDown(self):
        pass


if __name__=="__main__":
    #Create test suite and run
    suite = unittest.makeSuite(TestUrlManager,'test')
    runner = unittest.TextTestRunner()
    runner.run(suite)
    
