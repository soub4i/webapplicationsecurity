WebSecurity
=============

**Description** :  *WebSecurity* is a PHP class to Help Devlopper to prevent a almost webapplication security fails:

			   
**A - Using Tor OR Proxy to access  your webapp;**

i)  Static Method UsingTor() return bool (if user use Tor Browser = True).

ii) Static Method UsingProxy() return bool (if user use Proxy Service,site,software = True).

**B - Prevent :** 

i)   **SQL injection** : By Using Static Method SQLinj(string) return string.

ii)  **XSS** (Cross Site Scripting) : By Using Static Method XSS(string)return string.

iii) **File Inclusion** :

a)**RFI** (Remote File Inclusion) : By Using Static Method RFI(string) return string.

b)**LFI** (Local File Inclusion)  : By Using Static Method LFI(string) return string.


**Using this class :** 
I - Create composer.json like this

{
	"require": {

        "soubai/webapplicationsecurity": "dev-master"
    }
}

II - create Test.php

III- require "vendor/autoload.php"; in Test.php

VI - WebSecurity::Method  //(call class methods eg : UsingTor(), XSS(string), ...)

V - Enjoy

----------
