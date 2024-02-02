# Mailing Box Analysis

I wanted a fast way to clean the thousands of emails in my mailing box. So, initially this project was designed to list unique addresses encountered in my mailing box and order them by number of occurrences. 
But I realised that it could be interesting to go a little bit further and try to qualify those emails, as I noticed that some phishing slipped through the cracks of the original filters. 
Now, this project allows for the rapid analysis of emails in *.eml format, to see whether they are suspicious.
It analyses parameters such as destination address, return path, authentication protocols, domain reputation and ip location.

### Dependencies

The following python modules are required 
* tabulate
* eml_parser

### Description

The script ```processing.py``` performs the email analysis. It takes as input the path of the folder containing *.eml files (acting as your mailbox), the destination address of the email address and the name of the output file for the results. Results are stored in json format. To each email in the input folder is associated a boolean indicating if it is identified as suspicious or not by the script, and also a number of occurrence, i.e. the number of time an email with the same source address has been seen in the input folder.

```python3 processing.py -e <email_address> -p <email_folder_path> -o <output-file>```

The script ```analysis.py``` outputs simple information on those results: 
* an ordering of the source email addresses according to their occurrences
* the source email addresses having sent a unique email
* the source email addresses having sent a unique email and considered suspicious

The script takes as input the output file created by ```processing.py```.

```python3 analysis.py -i <input-file>```


### Pre-requisites

You have to create a folder containing all the emails you wish to analyse in .eml format.
In order to use the third party domain reputation service, you have to store an environment variable ```API_KEY``` containing your api key. The service used in this project is [Ip Quality Score](https://ipqualityscore.com). The environment variable is read automatically.

### Help

```
python3 processing.py -h
python3 analysis.py -h
```
