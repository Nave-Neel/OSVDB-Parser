#Class that makes url requests,and calls on HtmlParser to parse the return
#Html code

import urllib2
from HtmlParser import *
from Vulnerability import *

class UrlManager:

    def __init__(self):
        pass

    #Gets a list of all the vulnerability ids on the search result page passed in
    def getList(self,url):
        response = urllib2.urlopen(url)
        html = response.read()
        htmlParser = HtmlParser(html)
        l = htmlParser.parseList()
        return l

    #Gets a vulnerability object based on the specific vulnerability page
    def getVulnerability(self,vulId):
        url = 'http://www.osvdb.org/show/osvdb/'+str(vulId)
        response = urllib2.urlopen(url)
        html = response.read()
        htmlParser = HtmlParser(html)
        valuesList = htmlParser.parseVulnerability()
        #if id is none, then return none
        if valuesList[0]==None:
            return None
        v = Vulnerability(valuesList[0],valuesList[1],valuesList[2],valuesList[3],valuesList[4],valuesList[5],valuesList[6],valuesList[7],valuesList[8],valuesList[9],valuesList[10],valuesList[11],valuesList[12],valuesList[13],valuesList[14],valuesList[15],valuesList[16],valuesList[17],valuesList[18],valuesList[19],valuesList[20])
        return v
