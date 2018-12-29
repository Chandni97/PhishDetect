from extract_feature import *

url = sys.argv[1]

try:
    page_response = requests.get(url, timeout=5)
except:
    print('error getting response !!!')
    exit()

try:
    soup = BeautifulSoup(page_response.content, 'html.parser')
    status = []
    hostname = url
    h = [(x.start(0), x.end(0)) for x in re.finditer('https://|http://|www.|https://www.|http://www.', hostname)]
    z = int(len(h))
    if z != 0:
        y = h[0][1]
        hostname = hostname[y:]
        h = [(x.start(0), x.end(0)) for x in re.finditer('/', hostname)]
        z = int(len(h))
        if z != 0:
            hostname = hostname[:h[0][0]]

    status.append(SSLfinal_State(url))

    dns = 1
    try:
        domain = whois.whois(url)
    except:
        dns = -1

    if dns == -1:
        status.append(1)
    else:
        status.append(domain_registration_length(domain))


    status.append(url_of_anchor(soup, domain))
    status.append(links_in_tags(soup, domain))
    status.append(redirect(url))

    if dns == -1:
        status.append(1)
    else:
        res = age_of_domain(domain)
        res = res/483.33
        status.append(res)

    status.append(web_traffic(url))


    wml_credentials = {
        "url": "https://us-south.ml.cloud.ibm.com",
        "username": "320ef4fe-c3f2-47be-a49b-c2dc0361b476",
        "password": "ff0b9ad0-20ea-4fbb-99aa-6eee23b97707"
    }

    headers = urllib3.util.make_headers(basic_auth='{username}:{password}'.format(username=wml_credentials['username'], password=wml_credentials['password']))
    url = '{}/v3/identity/token'.format(wml_credentials['url'])
    response = requests.get(url, headers=headers)
    mltoken = json.loads(response.text).get('token')

    header = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + mltoken}

    # NOTE: manually define and pass the array(s) of values to be scored in the next line
    payload_scoring = {"fields": ["sslfinal_state", "domain_registation_length", "url_of_anchor", "links_in_tags", "redirect", "age_of_domain", "web_traffic"], "values": [status]}

    response_scoring = requests.post('https://us-south.ml.cloud.ibm.com/v3/wml_instances/441e4969-2a2b-449f-9bfd-005b4ba7620e/deployments/2e8859ae-88fc-44bc-b960-1c16e5af67d0/online', json=payload_scoring, headers=header)
    print("Scoring response")
    print(json.loads(response_scoring.text))

except:
    print('error getting features!!!')
    exit()

