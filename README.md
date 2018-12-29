# PhishDetect
Detecting phishing website using machine learning

Phishing is a type of attack where an attacker tricks the victim to give up sensitive information such as login credentials by disguising as a trustworthy entity. In this application we will try to detect a phishing website using the features that differentiates these domains from the legitimate ones. We will create our own dataset, train and test various machine learning models to detect phishing websites in real time.

Various features that are used to create the dataset are as follows : 
1. Using IP Address - check if URL has an ip address in it
1. HTTPS - checking the existance of 'https', trusted certificate authority and age of certificate
1. URL Short - check if url has been shortened
1. Having @ symbol - it leads the browser to ignore everything preceding the '@' symbol
1. Having double-slash - means that the user will be redirected (http://www.legitimate.com//http://www.phishing.com)
1. Domain registration Length - Trustworthy domains are regularly paid for several years
1. favicon - favicon loaded from the domain or not
1. Existance of https token in the domain part of the URL
1. Request URL - examines  whether  the  external  objects  contained  within  a  webpage are loaded from another domain
1. URL of Anchor - If the <a> tags and the website have different domain names
1. Links in tags - It is expected that tags (<Meta>, <Script> and <Link>) are linked to the same domain of the webpage.
1. Server Form Handler - If it is blank or contains any other domain name
1. Submitting information to email
1. Abnormal URL - if domain name (from whois) not in url
1. redirect count
1. invisible iframe
1. Age of domain 
1. web traffic - google rank for page
1. statistical report - match it with top 10 domains and top 10 IPs from PhishTank

## Creating Dataset

The URLs for phishing websites was retrieved from [here](https://www.phishtank.com/developer_info.php) (verified_online.csv) and
The URLs for legitimate websites was retrieved from [here](http://s3.amazonaws.com/alexa-static/top-1m.csv.zip) (top1m.csv)

1. Create the dataset for the phishing websites

python create_dataset.py <file_with_phishing_url> <number_of_urls_to_use> <output_file> <target_value>

```
python create_dataset.py verified_online.csv 500 dataset2.csv 1
```
1. Create the dataset for the legitimate websites

python create_dataset.py <file_with_legitimate_url> <number_of_urls_to_use> <output_file> <target_value>

```
python create_dataset.py top1m.csv 500 dataset2.csv 0
```

## Test different algorithms on Watson Studio

1. After the dataset has been created, login it to Watson Studio, create a project and import the notebook available in the repository.
1. Import the dataset that you have created previously
1. Use different feature selection methods to check which features are most important. In this notebook we have used random forest feature importance .
1. Try different machine learning models and compare the results. Our dataset works best with logistic regression. 
1. Create a logistic regression model on watson studio using the reduced dataset.
1. Get the access token of the machine learning model and url of the deployment


## Test a URL


```
python check_url.py <url>
```








