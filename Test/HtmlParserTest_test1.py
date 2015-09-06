#Unittest module for HtmlParser class
#The test input for this comes from the test1.htm file.
#Note that for some reason, I was not able to read directly from the file.
#Thus, the input to the test has to be done manually via a raw_input call at runitme

import sys
sys.path.append('..\Src')

from HtmlParser import *
import unittest

class TestHtmlParser(unittest.TestCase):

    #Setup an instance of HtmlParser to test
    def setUp(self):
        html = raw_input("Html: ")
        self.htmlParser = HtmlParser(html)

    #Test the various parsing functions
        
    def test_idenParser(self):
        assert self.htmlParser.idenParser() == 89551
        
    def test_titleParser(self):
        assert self.htmlParser.titleParser() == 'GNOME clutter Unmasked Password Field Cleartext Credential Disclosure'

    def test_viewsParser(self):
        self.htmlParser.viewsParser() == 43
        
    def test_dDParser(self):
        assert self.htmlParser.dDParser() == '2012-10-06'

    def test_descriptionParser(self):
        assert self.htmlParser.descriptionParser() == "GNOME contains a flaw in clutter that may lead to unauthorized disclosure of potentially sensitive information. The issue is due to the program displaying the unmasked password field in cleartext. This may allow a physically proximate attacker to gain access to credential information when looking at a user's screen."

    def test_locationParser(self):
        assert self.htmlParser.locationParser() == 'Physical Access Required'

    def test_attackTypeParser(self):
        assert self.htmlParser.attackTypeParser() == 'Cryptographic,Information Disclosure'

    def test_impactParser(self):
        assert self.htmlParser.impactParser() == 'Loss of Confidentiality'

    def test_solutionParser(self):
        assert self.htmlParser.solutionParser() == 'Patch / RCS'

    def test_exploitParser(self):
        assert self.htmlParser.exploitParser() == 'Exploit Public'

    def test_disclosureParser(self):
        assert self.htmlParser.disclosureParser() == 'Vendor Verified'

    def test_specSolutionParser(self):
        assert self.htmlParser.specSolutionParser() == 'The vendor has released a patch to address this vulnerability. There are no known workarounds or upgrades to correct this issue. Check the vendor advisory, changelog, or solution in the references section for details.'

    def test_creditParser(self):
        assert self.htmlParser.creditParser() == 'Alejandro Piñeiro Iglesias'

    def test_cvssAccessVecParser(self):
        assert self.htmlParser.cvssAccessVecParser() == None

    def test_authenticationParser(self):
        assert self.htmlParser.authenticationParser() == None

    def test_confidentialityParser(self):
        assert self.htmlParser.confidentialityParser() == None

    def test_integrityParser(self):
        assert self.htmlParser.integrityParser() == None

    def test_availabilityParser(self):
        assert self.htmlParser.availabilityParser() == None

    def test_baseScoreParser(self):
        assert self.htmlParser.baseScoreParser() == None
    
    def tearDown(self):
        pass

    
if __name__=="__main__":
    #Create test suite and run
    suite = unittest.makeSuite(TestHtmlParser,'test')
    runner = unittest.TextTestRunner()
    runner.run(suite)
    


