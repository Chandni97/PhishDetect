from extract_feature import *

def main():

   urlFile = sys.argv[1]
   urlTotal = sys.argv[2]
   outputFile = sys.argv[3]
   targetValue = sys.argv[4]

   df = pd.read_csv(urlFile)
   urls = df['url'].tolist()

   outfile = open(outputFile, "a", newline='')
   writer = csv.writer(outfile)

   for i in range(0,int(urlTotal)):
       url = urls[i]
       if "http://" not in url and "https://" not in url:
           url = "https://"+url
       if url.count('.') > 1:
           continue
       print(str(i) + ' : ' + url)
       try:
            page_response= requests.get(url, timeout=5)
       except:
           print('error page response')
           continue

       soup = BeautifulSoup(page_response.content, 'html.parser')
       status=[]

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


       try:
           status.append(url_having_ip(url))
           status.append(SSLfinal_State(url))
           status.append(url_short(url))
           status.append(having_at_symbol(url))
           status.append(doubleSlash(url))

           dns = 1
           try:
               domain = whois.whois(url)
           except:
               dns = -1

           if dns == -1:
               status.append(1)
           else:
               status.append(domain_registration_length(domain))


           status.append(favicon(soup, domain))

           status.append(https_token(url))
           status.append(request_url(soup, domain))
           status.append(url_of_anchor(soup, domain))
           status.append(links_in_tags(soup, domain))
           status.append(sfh(soup, domain))
           status.append(submitting_to_email(soup))


           if dns == -1:
               status.append(1)
           else:
               status.append(abnormal_url(domain, url))


           status.append(redirect(url))
           status.append(iframe(soup))



           if dns == -1:
               status.append(1)
           else:
               status.append(age_of_domain(domain))

           status.append(web_traffic(url))
           status.append(statistical_report(url, hostname))
           status.append(int(targetValue))
           writer.writerow(status)

       except:
           print('error')
           continue

       features = ['1. url having ip', '2. sslfinal_state', '3. url_short', '4. having_at_symbol', '5. doubleslash', '6. domain_registation_length'
                   , '7. favicon', '8. https_token', '9. request_url', '10. url_of_anchor', '11. links_in_tags', '12. sfh', '13. submitting_to_email',
                   '14. abnormal url', '15. redirect', '16. iframe', '17. age_of_domain', '18. web_traffic', '19. google_index', '20. statistical_report']

       # index = 0
       # for feature in features:
       #     print(feature + ' : ' + str(status[index]))
       #     index = index + 1

if __name__ == "__main__":
         main()
