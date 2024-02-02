
import argparse
import json
import pprint

# installed modules
import numpy as np

pp = pprint.PrettyPrinter(indent=4)

senders_dict = None

"""
    command line arguments
"""
parser = argparse.ArgumentParser(
    prog='Email analyser'
    )
# output file
parser.add_argument(
    "-i",
    "--input",
    required=True,
    help="Provide the name of input file where results are stored"
    )

args = parser.parse_args()
input = args.input

# Open the file for reading
with open(input, "r") as fp:
    # Load the dictionary from the file
    senders_dict = json.load(fp)

# number of unique email addresses
print(f"Number of unique email addresses: {len(senders_dict.keys())}")

# number of email adddress sending only one mail
count = 0
count_suspicious = 0
unique_mail_suspicious_list = list()
for elmt in senders_dict:
	if senders_dict[elmt]["count"] == 1:
		count+=1
		if senders_dict[elmt]["suspicious"] == True:
			count_suspicious+=1
			unique_mail_suspicious_list.append(elmt)
# print(f"Number of mail addresses sending a single email: {count}")
# print(f"Number of suspicious mail addresses sending a single email: {count_suspicious}")
# print(unique_mail_suspicious_list)

# order received emails per descending order
sorted_dict = sorted(senders_dict.items(), key = lambda x: x[1]['count'])
     
pp.pprint(sorted_dict)


