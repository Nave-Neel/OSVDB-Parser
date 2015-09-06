-----What is this-----
This is a simple python program that parses the result page of the advanced search feature on the OSDVB website (http://www.osvdb.org/search/advsearch).
Information on each vulnerability is collected and stored in a local database.
This allows a user to make multiple queries on the OSDVB website in a day and store them for later reference or analysis



----How to use----
Please look at the User_manual.txt for directions.



----Design/Future maintainence information----
The structure of the program is quite simple. There are 6 files and 4 classes.
Below is a description of each class:

Vulnerability: This class models an individual vulnerability 

UrlManager: This class interacts with the driver to return the vulnerability object. It fetches the html code of a webpage and then 
            invokes HtmlParser to parse it.

HtmlParser: This does most of the heavy work in the program. If the OSDVB site changes in the future,the individual methods of this class 
            shoulb be re-written.

DatabaseManager: This is the main interface to the database. It handles connections with the database,insertion of vulnerabilites into 
                 the database and error handling associated with the database

				 
				 
----Database----
The program uses a mySQL database to store the data.Details on how to setup the database are in User_manual.txt and the database schema is 
in the db folder.



----Testing----
The test code implements the unittest module in python.The test code is found in the test folder.  
Each method in each class is tested separately (method-level testing) 