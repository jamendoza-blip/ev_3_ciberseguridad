# ZAP Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 0 |
| Low | 1 |
| Informational | 5 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| Medium | Exceeded High | http://securedev-app:5000 | Percentage of responses with status code 4xx | 89 % |
| Low | Warning |  | ZAP errors logged - see the zap.log file for details | 3    |
| Low | Warning |  | ZAP warnings logged - see the zap.log file for details | 6    |
| Info | Informational | http://securedev-app:5000 | Percentage of responses with status code 2xx | 9 % |
| Info | Informational | http://securedev-app:5000 | Percentage of responses with status code 3xx | 1 % |
| Info | Informational | http://securedev-app:5000 | Percentage of endpoints with content type text/html | 100 % |
| Info | Informational | http://securedev-app:5000 | Percentage of endpoints with method GET | 80 % |
| Info | Informational | http://securedev-app:5000 | Percentage of endpoints with method POST | 20 % |
| Info | Informational | http://securedev-app:5000 | Count of total endpoints | 5    |







## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Cookie Slack Detector | Low | 1 |
| Authentication Request Identified | Informational | 1 |
| Cookie Slack Detector | Informational | 1 |
| Non-Storable Content | Informational | Systemic |
| Session Management Response Identified | Informational | 1 |
| User Agent Fuzzer | Informational | Systemic |




## Alert Detail



### [ Cookie Slack Detector ](https://www.zaproxy.org/docs/alerts/90027/)



##### Low (Low)

### Description

Repeated GET requests: drop a different cookie each time, followed by normal request with all cookies to stabilize session, compare responses against original baseline GET. This can reveal areas where cookie based authentication/attributes are not actually enforced.

* URL: http://securedev-app:5000/login
  * Node Name: `http://securedev-app:5000/login`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `NOTE: Because of its name this cookie may be important, but dropping it appears to have no effect: [sd_session]
Cookies that don't have expected effects can reveal flaws in application logic. In the worst case, this can reveal where authentication via cookie token(s) is not actually enforced.
These cookies affected the response: 
These cookies did NOT affect the response: sd_session
`


Instances: 1

### Solution



### Reference


* [ https://cwe.mitre.org/data/definitions/205.html ](https://cwe.mitre.org/data/definitions/205.html)


#### CWE Id: [ 205 ](https://cwe.mitre.org/data/definitions/205.html)


#### WASC Id: 45

#### Source ID: 1

### [ Authentication Request Identified ](https://www.zaproxy.org/docs/alerts/10111/)



##### Informational (High)

### Description

The given request has been identified as an authentication request. The 'Other Info' field contains a set of key=value lines which identify any relevant fields. If the request is in a context which has an Authentication Method set to "Auto-Detect" then this rule will change the authentication to match the request identified.

* URL: http://securedev-app:5000/login
  * Node Name: `http://securedev-app:5000/login ()(_csrf,password,username)`
  * Method: `POST`
  * Parameter: `username`
  * Attack: ``
  * Evidence: `password`
  * Other Info: `userParam=username
userValue=ZAP
passwordParam=password
referer=http://securedev-app:5000/login
csrfToken=_csrf`


Instances: 1

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/auth-req-id/)



#### Source ID: 3

### [ Cookie Slack Detector ](https://www.zaproxy.org/docs/alerts/90027/)



##### Informational (Low)

### Description

Repeated GET requests: drop a different cookie each time, followed by normal request with all cookies to stabilize session, compare responses against original baseline GET. This can reveal areas where cookie based authentication/attributes are not actually enforced.

* URL: http://securedev-app:5000/login
  * Node Name: `http://securedev-app:5000/login ()(_csrf,password,username)`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: ``
  * Other Info: `Dropping this cookie appears to have invalidated the session: [sd_session] A follow-on request with all original cookies still had a different response than the original request.
`


Instances: 1

### Solution



### Reference


* [ https://cwe.mitre.org/data/definitions/205.html ](https://cwe.mitre.org/data/definitions/205.html)


#### CWE Id: [ 205 ](https://cwe.mitre.org/data/definitions/205.html)


#### WASC Id: 45

#### Source ID: 1

### [ Non-Storable Content ](https://www.zaproxy.org/docs/alerts/10049/)



##### Informational (Medium)

### Description

The response contents are not storable by caching components such as proxy servers. If the response does not contain sensitive, personal or user-specific information, it may benefit from being stored and cached, to improve performance.

* URL: http://securedev-app:5000
  * Node Name: `http://securedev-app:5000`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: http://securedev-app:5000/
  * Node Name: `http://securedev-app:5000/`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: http://securedev-app:5000/login
  * Node Name: `http://securedev-app:5000/login`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: http://securedev-app:5000/robots.txt
  * Node Name: `http://securedev-app:5000/robots.txt`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``
* URL: http://securedev-app:5000/sitemap.xml
  * Node Name: `http://securedev-app:5000/sitemap.xml`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `no-store`
  * Other Info: ``

Instances: Systemic


### Solution

The content may be marked as storable by ensuring that the following conditions are satisfied:
The request method must be understood by the cache and defined as being cacheable ("GET", "HEAD", and "POST" are currently defined as cacheable)
The response status code must be understood by the cache (one of the 1XX, 2XX, 3XX, 4XX, or 5XX response classes are generally understood)
The "no-store" cache directive must not appear in the request or response header fields
For caching by "shared" caches such as "proxy" caches, the "private" response directive must not appear in the response
For caching by "shared" caches such as "proxy" caches, the "Authorization" header field must not appear in the request, unless the response explicitly allows it (using one of the "must-revalidate", "public", or "s-maxage" Cache-Control response directives)
In addition to the conditions above, at least one of the following conditions must also be satisfied by the response:
It must contain an "Expires" header field
It must contain a "max-age" response directive
For "shared" caches such as "proxy" caches, it must contain a "s-maxage" response directive
It must contain a "Cache Control Extension" that allows it to be cached
It must have a status code that is defined as cacheable by default (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501).

### Reference


* [ https://datatracker.ietf.org/doc/html/rfc7234 ](https://datatracker.ietf.org/doc/html/rfc7234)
* [ https://datatracker.ietf.org/doc/html/rfc7231 ](https://datatracker.ietf.org/doc/html/rfc7231)
* [ https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html ](https://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)


#### CWE Id: [ 524 ](https://cwe.mitre.org/data/definitions/524.html)


#### WASC Id: 13

#### Source ID: 3

### [ Session Management Response Identified ](https://www.zaproxy.org/docs/alerts/10112/)



##### Informational (Medium)

### Description

The given response has been identified as containing a session management token. The 'Other Info' field contains a set of header tokens that can be used in the Header Based Session Management Method. If the request is in a context which has a Session Management Method set to "Auto-Detect" then this rule will change the session management to use the tokens identified.

* URL: http://securedev-app:5000/login
  * Node Name: `http://securedev-app:5000/login`
  * Method: `GET`
  * Parameter: `sd_session`
  * Attack: ``
  * Evidence: `sd_session`
  * Other Info: `cookie:sd_session`


Instances: 1

### Solution

This is an informational alert rather than a vulnerability and so there is nothing to fix.

### Reference


* [ https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/ ](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/session-mgmt-id/)



#### Source ID: 3

### [ User Agent Fuzzer ](https://www.zaproxy.org/docs/alerts/10104/)



##### Informational (Medium)

### Description

Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response.

* URL: http://securedev-app:5000
  * Node Name: `http://securedev-app:5000`
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://securedev-app:5000/
  * Node Name: `http://securedev-app:5000/`
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://securedev-app:5000/login
  * Node Name: `http://securedev-app:5000/login`
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)`
  * Evidence: ``
  * Other Info: ``
* URL: http://securedev-app:5000/login
  * Node Name: `http://securedev-app:5000/login`
  * Method: `GET`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``
* URL: http://securedev-app:5000/login
  * Node Name: `http://securedev-app:5000/login ()(_csrf,password,username)`
  * Method: `POST`
  * Parameter: `Header User-Agent`
  * Attack: `Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)`
  * Evidence: ``
  * Other Info: ``

Instances: Systemic


### Solution



### Reference


* [ https://owasp.org/www-project-web-security-testing-guide/ ](https://owasp.org/www-project-web-security-testing-guide/)



#### Source ID: 1


