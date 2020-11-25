<hr>
 <h1 align="center">Burp to Slack</h1>
 
 <p align="center">
<img src="pic.PNG"  />
</p>

<hr>
Push notifications to Slack channel or to custom server based on BurpSuite response conditions.

### Burp to Slack
Burp2Slack extension matches all BurpSuite traffics (Intruder, Repeater, Proxy and Scanner) based on "any" of the user input conditions such as, 
- If the input string exists in the response body
- If the input string exists in the response headers
- If the response content-length is (equal, greater than, less than or doesn't equal) the user input content length
- If the input status code matches the response one.

When one of the above conditions met, then it pushes a notification to either a Slack channel or Custom server. The notification message is customized and can be edited/formatted by the user to get the met "condition/s" and/or the HTTP response body that includes the conditions. 
### Main Features
* Poll Notifications every X seconds.
* Customize your notification using {{FOUND}} which is your input condition and {{BODY}} which returns response body.
* Match response body, HTTP headers, content length and HTTP status code.
* Use the logical operators !, =, < and > in the content length field.
* Support both Slack webhook and custom HTTP listeners.
* Match Burp proxy, Repeater, Intruder and Scanner/Spider.

#### TODO:
     - [ ] BurpCollaborator to Slack
     - [ ] Match more options 


#### Bugs / Feedback / PRs
Any comment, issue or pull request will be highly appreciated :)

#### Author
b1twis3 - https://twitter.com/fasthm00
