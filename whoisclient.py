""" Author: Mohammad Khorram AKA bleed-x

    About a program: a simple script that parse a csv file of domains and check the creation date of domains.
    if a domain creation date is less than 30 days it might be malicious, since some malwares like DGA malwares use newly registred domains.
    
    [*] Internet connection required

    Instructions:
        1- Declear the path of the csv file
        2- Play some fortnite :)
        3- the output.log file which contains possibly malicious domains will create in the same directory as the sciprt executed   
        
        
     Whois library supported TLDs: 
         download - biz - edu - education - com - download - info - me  - club
         org - io - xyz - tel - online - wiki - press - pharmacy - rest
         mobi - name - net - ninja - nyc - online - security - website
         site - space - store - tech - tel - theatre - tickets - video  
"""


import whois
import datetime
import time
import logging
import os
import pandas as pd
import sys

""" Reading the csv file with pandas"""
def getdomains(file_path):
    try:
        global data
        data=pd.read_csv(file_path)
        logging.info("[*] Script executed at %s "%os.popen('date').read())
        """ save the current OS time in the output log """
        print ("[*] File imported please wait... ")
    except FileNotFoundError:
        print ("[*] File/Path not found ")
        sys.exit()
   
        
""" Get current day to calculate the diffrence between system date and domain creation date"""
def getcurrentday():
    global today_date
    today_date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")



""" if domain creation date is less than 30 days it's possibly malicious"""
def run():
   for item in range(len(data)):
      try: 
          time.sleep(3)
          domain=whois.query(data.values[item,0])
          domain_creation=domain.creation_date
          datetimeFormat = '%Y-%m-%d %H:%M:%S'
          diff = datetime.datetime.strptime(str(today_date), datetimeFormat) - datetime.datetime.strptime(str(domain_creation), datetimeFormat)
          if (int(diff.days) < 30):
             print ("%s domain is possibly malicious"%data.values[item,0])
             logging.info("[*] %s domain is probably malicious. domain creation date is %s"%(data.values[item,0] , domain_creation)) 
          else:
              print ("%s domain creation date is : %s "%(data.values[item,0] , domain_creation))

      except KeyboardInterrupt:
        print ("[*] Program exited")
        sys.exit()
        
      except Exception as im :
            if "DOMAIN NOT FOUND" in str(im):
                print ("[*] ERROR : %s domain not found "%data.values[item,0])
            elif "Unknown TLD" in str(im) :
                print ("[*] ERROR : %s domain has an unknown TLD "%data.values[item,0])
            else:
                continue


if __name__ == "__main__":  
    
    global file_path
    try:
        file_path=input("[*] Please Enter a file path : (e.g /home/user/Desktop/maldomains.csv) \n")
    except KeyboardInterrupt:
        print ("[*] Program exited")
        sys.exit()
        
    logging.basicConfig(filename=".//output.log" , level=logging.INFO)
    """ Path to log file which will store malicious domains """
    
    
   

    getdomains(file_path)
    getcurrentday()
    run()
    
    print("[*] script finished ")
    logging.info("[*] script finished at %s " %os.popen('date').read())
