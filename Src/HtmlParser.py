#Class that parses html code to return information about the vulnerabilites
#Has 2 main methods - parseList and parseVulnerability which call on the other methods

class HtmlParser:

    #Construtor for HtmlParser Class
    def __init__(self,htmlToParse):
        #contains a list of individual lines of the html code to parse
        self.html= htmlToParse
        self.decode()
        self.html=self.html.split('\n')


    #Difference between " and ' in python
    #Short answer: almost no difference except stylistically.
    #Short blurb: If you dont want to escape the quote characters inside your string, use the other type
    def decode(self):
        htmlCodes = {'&#33':'!','&#39;':"'" ,'&quot;': '"','&gt;':'>','&lt;':'<','&amp;':'&'}
        for code in htmlCodes:
            self.html = self.html.replace(code,htmlCodes[code])

                
    #Parses the main OSDVB search results page to return a list of vulnerability Ids
    def parseList(self):
        l = None
        for line in self.html:
            if line.find('<a href="/show/osvdb/')==0:
                if l == None:
                    l = []
                end = line.find("onclick")
                vulId = line[21:end-2]
                l.append(vulId)
        return l


    #Parses an individual vulnerability information page to return a vulnerability object
    def parseVulnerability(self):
        #a list of the different parsing functions whic are to be ran sequentially
        parseFunctionsList = [self.idenParser,self.titleParser,self.viewsParser,self.dDParser,self.descriptionParser,self.locationParser,self.attackTypeParser,self.impactParser,self.solutionParser,self.exploitParser,self.disclosureParser,self.osdvbParser,self.specSolutionParser,self.creditParser,self.baseScoreParser,self.cvssAccessVecParser,self.cvssAccessCompParser,self.authenticationParser,self.confidentialityParser,self.integrityParser,self.availabilityParser]
        parsedValues=[]
        for f in parseFunctionsList:
           parsedValues.append(f())
        return parsedValues


    #Removes lines from the html code that have already been parsed, so that subsequent parsing functions do not have to iterate over this code
    def removeLines(self,lineCount):
        #check to see that we are not at end of html code -- impt as functions lineCount may run till the end if they do not find the code they are looking for
        if self.html[lineCount-2] == '</html>':
            return
        self.html.reverse()
        for x in range(0, lineCount):
            self.html.pop()
        self.html.reverse()
        return            

   
    #Parses html code to return the Id of the vulnerability
    def idenParser(self):
        iden = None
        for line in self.html:
            if line.find('<title>')!=-1:
                ind=line.find(':')
                iden = line[7:ind]
                break
        try:
            return int(iden)
        except:
            return None

        
    #Parses html code to return the title of the vulnerability   
    def titleParser(self):
        title = None
        lineNumber=0
        for line in self.html:
            lineNumber+=1
            if line.find('<title>')!=-1:
                ind=line.find(':')
                ind2=line.find('</title>')
                break
        self.removeLines(lineNumber)
        try:
            title = line[ind+2:ind2]
            return title
        except:
            return None


    #Parses html code to return the total view count of the vulnerability
    #STH WRONG
    def viewsParser(self):
        views=None
        lineNumber=0
        state=0
        count=0
        for line in self.html:
            lineNumber+=1
            #state which looks for line to begin parsing
            if(state==0):
                if line.find('Views All Time')!=-1 :
                    state=1
                    continue
            #state which skips over a fixed number of lines
            if(state==1):
                count+=1
                if count == 8:
                    state = 2
                    continue
            #state which parses the lines with the information needed
            if(state==2):
                ind = line.find('</td>')
                break
        self.removeLines(lineNumber)
        try:
            views = line[0:ind-1]
            try:
                 views = int(views)
            except:
                views = None
        except:
            views = None
        return views

    
    #Parses html code to return the disclosure date of the vulnerability
    def dDParser(self):
        dD=None
        lineNumber=0
        state=0
        for line in self.html:
            lineNumber+=1
            #state which looks for line to begin parsing
            if(state==0):
                if line.find('Disclosure Date')!=-1:
                    state=1
                    continue
            #state which skips over the next line
            if(state==1):
                state=2
                continue
            #state which parses the lines with the information needed
            if(state==2):
                ind = line.find('>')
                ind2 = line.find('</td>')
                break
        self.removeLines(lineNumber)
        try:
             dD = line[ind+1:ind2]
             #Check if it is of the format ('yyyy-mm-dd')
             if len(dD) != 10 or dD[4]!='-' or dD[7]!='-':
                 dD = None
        except:
             dD = None
        return dD


    #Parses html code to return the description of the vulnerability     
    def descriptionParser(self):
        description=None
        lineNumber=0
        state=0
        for line in self.html:
            lineNumber+=1
            #state which looks for line to begin parsing
            if(state==0):
                if line.find('Description</h1></td>')!=-1:
                    state=1
                    continue
            #state which skips over a line
            if(state==1):
                description=""
                state=2
                continue
            #state which parses the lines with the information needed
            if(state==2):
                description += line
                if line.find('</p>')!=-1:
                    break
        self.removeLines(lineNumber)
        try:
            description = description[3:len(description)-4]
        except:
            description = None
        return description


    #General function that parses html code to return the classification
    #of the vulnerability. The specific category to be parsed is sent as a
    #parameter to the function
    def classificationParser(self,categoryStr):
        category = None
        state=0
        lineNumber=0
        for line in self.html:
            lineNumber+=1
            #state which looks for line to begin parsing
            if state == 0:
                if line.find(categoryStr)!=-1:
                    state=1
                    category=""
                    continue
            #state which parses the lines with the information needed
            if state == 1:
                if line.find('<br/>')!=-1:
                    break
                category += line       
        self.removeLines(lineNumber)
        return category


    #Parses html code to return the location classification of the vulnerability       
    def locationParser(self):
        return self.classificationParser('<b>Location</b>:')


    #Parses html code to return the attack type classification of the vulnerability
    def attackTypeParser(self):
        return self.classificationParser('<b>Attack Type</b>:')


    #Parses html code to return the impact classification of the vulnerability
    def impactParser(self):
        return self.classificationParser('<b>Impact</b>:') 


    #Parses html code to return the solution classification of the vulnerability
    def solutionParser(self):
        return self.classificationParser('<b>Solution</b>:')


    #Parses html code to return the exploit type classification of the vulnerability
    def exploitParser(self):
        return self.classificationParser('<b>Exploit</b>:')


    #Parses html code to return the disclosure classification of the vulnerability
    def disclosureParser(self):
        return self.classificationParser('<b>Disclosure</b>:')


    #Parses html code to return the OSDVB classification of the vulnerability
    def osdvbParser(self):
        return self.classificationParser('<b>OSDVB</b>:') 


    #Parses html code to return the specific solution for the vulnerability
    def specSolutionParser(self):
        specSolution = None
        state=0
        lineNumber=0
        for line in self.html:
            lineNumber+=1
            #state which looks for line to begin parsing
            if state == 0:
                if line.find('Solution</h1></td>')!=-1:
                
                    state=1
                    specSolution=""
                    continue
            #state which skips over a line
            if state == 1:
                state=2
                continue
            #state which parses the lines with the information needed
            if state == 2:
                specSolution+=line
                if line.find('</p>')!=-1:
                    break
        self.removeLines(lineNumber)
        try:
            specSolution = specSolution[3:len(specSolution)-4]
        except:
            specSolution = None
        return specSolution


    #Parses html code to return the credit information for the vulnerability
    def creditParser(self):
        credit = None
        state=0
        lineNumber=0
        count = 0
        for line in self.html:
            lineNumber+=1
            #state which looks for line to begin parsing
            if state == 0:
                if line.find('Credit</h1></td>')!=-1:
                    state=1
                    credit=""
                    continue
            #state which skips over a fixed number of lines
            if state == 1:
                count+=1
                if count == 2:
                    state=2
                continue
            #state which parses the lines with the information needed
            if state == 2:
                if line.find("<li>")==-1:
                    break
                if credit != "":    #inserts a "," between 2 different creditees
                    credit+=","
                c=0 #variable which is used to insert a "-" between different parts of the creditees information 
                while line.find('<a href')!= -1:
                    if c != 0:
                        credit+="-"
                    c+=1
                    ind = line.find('">')
                    ind2 = line.find('</a>')
                    try:
                        credit += line[ind+2:ind2]
                        line = line[ind2+4:len(line)]
                    except:
                        return None
                
        self.removeLines(lineNumber)
        return credit  


    #General method that parses html code to return information related to
    #a particular cvssv2 score category(if any).Note that the info is in images.
    #Hence,we cannot parse this. However, we can look at the image names to find
    #the classification for each particular category in the cvssv2 score.
    def cvssImageParser(self,category):
        value = None
        lineNumber=0
        for line in self.html:
            lineNumber+=1
            if line.find('<img alt="'+category)!=-1:
                ind = line.find('src')
                break
        try:
            value = int(line[ind-3:ind-2])
        except:
            value=None
        self.removeLines(lineNumber)
        return value


    #Parses html code to return the acess vector classification for the vulnerability
    def cvssAccessVecParser(self):
        score =  self.cvssImageParser('Access_vector')
        #this looks ugly but python does not have switch statements.....
        if score == 0:
            return 'local'
        if score == 1:
            return 'adjacent network'
        if score == 2:
            return 'remote'

        
    #Parses html code to return the access complexity for the vulnerability    
    def cvssAccessCompParser(self):
        score = self.cvssImageParser('Access_complexity')
        if score == 0:
            return 'high'
        if score == 1:
            return 'medium'
        if score == 2:
            return 'low'


    #Parses html code to return the authenication score for the vulnerability
    def authenticationParser(self):
        score = self.cvssImageParser('Authentication')
        if score == 0:
            return 'multiple instances'
        if score == 1:
            return 'simple instance'
        if score == 2:
            return 'none'


    #Parses html code to return the confidentailty classification for the vulnerability
    def confidentialityParser(self):
        score = self.cvssImageParser('Confidentiality_impact')
        if score == 0:
            return 'none'
        if score == 1:
            return 'partial'
        if score == 2:
            return 'complete'


    #Parses html code to return the integrity classification for the vulnerability
    def integrityParser(self):
        score = self.cvssImageParser('Integrity_impact')
        if score == 0:
            return 'none'
        if score == 1:
            return 'partial'
        if score == 2:
            return 'complete'


    #Parses html code to return the integrity classification for the vulnerability 
    def availabilityParser(self):
        score = self.cvssImageParser('Availability')
        if score == 0:
            return 'none'
        if score == 1:
            return 'partial'
        if score == 2:
            return 'complete'


    #Parses html code to return the cvssv2 base score for the vulnerability
    def baseScoreParser(self):
        score = None
        for line in self.html:
            if line.find('CVSSv2 Base Score')!=-1:
                 ind = line.find('=')
                 break
        try:
            score = int(score[ind+1:len(line)-2])
        except:
            score = None
        return score
            
