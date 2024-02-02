import argparse
import requests
import datetime
import requests
import pprint
import json
import time
import os

# installed modules
import eml_parser
from tabulate import tabulate


API_KEY_Ipqualityscore = os.getenv('API_KEY') # None
pp = pprint.PrettyPrinter(indent=4)


"""
    command line arguments
"""
parser = argparse.ArgumentParser(
    prog='Email analyser'
    )
# path of email folder 
parser.add_argument(
    '-p', 
    '--pathname', 
    required=True,
    help="Provide absolute path of the folder containing the emails")
# destination email
parser.add_argument(
    "-e",
    "--email",
    required=True,
    help="Provide email address to check as the destination"
    )
# output file
parser.add_argument(
    "-o",
    "--output",
    required=True,
    help="Provide the name of the output file where to store results"
    )

args = parser.parse_args()
path = args.pathname
# format pathname
if path[-1] != "/":
    path += "/"
email = args.email
output = args.output

"""
    processing
"""

def json_serial(obj):
    if isinstance(obj, datetime.datetime):
        serial = obj.isoformat()
        return serial

def inspect(parsed_eml, email_address):
    col_names = ["Analysis parameters", "Result"]
    data = list()
    suspicious_to = False
    suspicious_rpath = False
    suspicious_protocols = False

    """
        header analysis
    """
    # check if "to" is a mailing list or my email
    if email_address not in parsed_eml["header"]["to"] :
        data.append(["Sent to mailing list", True])
        suspicious_to = True

    # check if "from" corresponds to return-path
    if parsed_eml["header"]["header"].get("return-path"):
        #get "from" domain
        from_email = parsed_eml["header"]["from"].split("@")[-1]
        #check that "from" domain is in at least an email in return-path field
        returnpath = [elmt for elmt in parsed_eml["header"]["header"]["return-path"] if from_email in elmt ]
        if len(returnpath) == 0: # domain match list is empty
            data.append(["Mismatching return path", True])
            suspicious_rpath = True

            # check return path reputation using third party service
            if API_KEY_Ipqualityscore:
                suspicious_returnpath = [elmt for elmt in parsed_eml["header"]["header"]["return-path"] if from_email not in elmt ]
                for elmt in suspicious_returnpath:
                    return_email = elmt.replace("<","").replace(">","")
                    r = requests.post(
                        "https://www.ipqualityscore.com/api/json/email/",
                        data={'key': API_KEY_Ipqualityscore, "timeout":60, "email":return_email})
                    # print(r.json())
                    
                    if r.json()["suspect"] == True :
                        #suspicious_rpath still True
                        pass 
                    else:
                        suspicious_rpath = False
                    
                
    #get email security protocols results
    protocols = ["dkim", "spf", "dmarc"]
    auth_results = list()
    if parsed_eml["header"]["header"].get("authentication-results"):
        for elmt in parsed_eml["header"]["header"]["authentication-results"][0].split(" "):
            for p in protocols:
                if p in elmt.split("=")[0]:
                    auth_results.append(elmt.split("="))
        for elmt in auth_results:
            if elmt[0] == "dkim" or elmt[0] == "spf":
                if elmt[1] != "pass" and elmt[1] != "neutral": 
                    data.append([elmt[0], elmt[1]])
                    suspicious_protocols = True
            elif elmt[0] == "dmarc":
                if "REJECT" in elmt[1]:
                    data.append([elmt[0], elmt[1]])
                    suspicious_protocols = True

    else:
        data.append(["Email security protocols", "None"])
        suspicious_protocols = True

    # get ip addresses location
    if suspicious_protocols or suspicious_rpath or suspicious_to:
        email_path = ""
        for elmt in parsed_eml["header"]["received_ip"]:
            response = requests.get(f'https://ipapi.co/{elmt}/json/').json()
            if response.get("country_name") != None:
                email_path = email_path + response.get("city") + "," + response.get("region") + "," + response.get("country_name") + " | "
            time.sleep(0.5)
        data.append(["Email path", email_path])
    

    #display table
    if suspicious_protocols or suspicious_rpath or suspicious_to:
        print("Analysis for email sent by " + parsed_eml["header"]["from"])
        print(tabulate(data, headers=col_names))
        
    
    return suspicious_rpath # let the return path have the most weight for now, since it is externally evaluated

# check if path exists 
if os.path.exists(path):
    count = 0
    senders_dict = dict()

    # get list of filenames
    filenames_list = os.listdir(path)
    #print(f"Here is the list of filenames in path {path}: {filenames_list}")
    
    for name in filenames_list:
        with open(path+name, "rb") as fhdl:
            raw_email = fhdl.read()
            count += 1 
        ep = eml_parser.EmlParser()
        parsed_eml = ep.decode_email_bytes(raw_email)

        # register sender and occurrence
        senders_dict.setdefault(parsed_eml["header"]["from"],{"count":0, "suspicious":False})
        senders_dict[parsed_eml["header"]["from"]]["count"] += 1

        # json.dumps(parsed_eml, default=json_serial)
        if senders_dict[parsed_eml["header"]["from"]]["count"] == 1: # first time seing this sender
            res=inspect(parsed_eml, email)
            if res:
                senders_dict[parsed_eml["header"]["from"]]["suspicious"] = res

    # Writing to output.json
    with open(output, "w") as outfile:
        json.dump(senders_dict, outfile) 
    
    pp.pprint(senders_dict)

else:
    print("Please provide a valid path")


