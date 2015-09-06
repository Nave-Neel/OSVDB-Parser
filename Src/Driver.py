#Main driver file for the program. Handles input from the user and the interaction between the classes

from UrlManager import *
from DatabaseManager import *
import re

#if __name __ == "__main__"

print("***********OSDVB Parser**************")

database = DatabaseManager()
urlManager = UrlManager()
exit = False
while exit is False:
    userUrl = raw_input("Enter Url String from OSDVB search: ")
    if userUrl.find('http://www.osvdb.org/search/')!=0:  #not the best validation
        print('Invalid Url Input...')
        continue
    vulList = urlManager.getList(userUrl)
    if vulList == None:
        print('Url cannot be parsed. Please check input...')
        continue
    for v in vulList:
        vul = urlManager.getVulnerability(v)
        if vul == None:
            print('Failed in adding vulnerability '+ v +' to database')
            continue
        fail = database.addVulnerability(vul)
        if(fail == True):
            print('Failed in adding vulnerability '+ v + ' to database')
            continue
        
    print("Add another search (y/n)?")
    user_in = input().upper()
    while user_in != 'N' and user_in != 'Y':
        print ("Invalid input.Try Again")
        print("Add another search (y/n)?")
        user_in = input().upper()
    if user_in == 'N':
        exit = True
        print("Exiting Program...")
    elif user_in == 'Y':
        continue
    








  
