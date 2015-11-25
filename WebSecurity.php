<?php
/*

 * IN THE NAME OF ALLAH
 *
 * @Name	WebSecur!ty Class
 * @version	0.1 Beta
 * @license	Apache Licence 2.0
 * @author	Abderrahim Soubai Elidrissi
 * @Date		25/03/2015
 *
 * @File		WebSecur!ty.class.php

Description :  WebSecurity is a PHP class to Help Devlopper to prevent a almost webapplication security fails:
			   
			   A - Using Tor OR Proxy to access  your webapp;
			   		i)  Static Method UsingTor() return bool (if user use Tor Browser = True).
			   		ii) Static Method UsingProxy() return bool (if user use Proxy Service,site,software = True).
			   B - Prevent : 
			   		i)   SQL injection : By Using Static Method SQLinj(string) return string.
			   		ii)  XSS (Cross Site Scripting) : By Using Static Method XSS(string)return string.
			   		iii) File Inclusion :
			   				a)RFI (Remote File Inclusion) : By Using Static Method RFI(string) return string.
				   			b)LFI (Local File Inclusion)  : By Using Static Method LFI(string) return string.

Using this class : 

					I -   include(WebSecur!ty.class.php);
					II -  WebSecurity::Method  //(call class methods eg : UsingTor(), XSS(string), ...)
					III - Enjoy


	*/

class WebSecurity
{
    /*
    Tor Browser Detector
    Return True if user browser is tor or false if not
    */	
    public static function UsingTor()
    {
        if (_IsTorExitPoint()) {
            return true;
        } else {
            return false;
        }
    }
    /*
    Proxy Detector
    Return True if user use Proxy service
    */
    public static function UsingProxy()
    {
        $ports = array(8080,80,81,1080,6588,8000,3128,553,554,4480);
        foreach($ports as $port) {
            if (@fsockopen($_SERVER['REMOTE_ADDR'], $port, $errno, $errstr, 30)) {
                return true;
            }
        }
        return false;
    }
    /*
    Search Bots (search engines) Detector
    Return True if Agent is Robot
    */
    static function IsBot(){
	if(!empty($_SERVER['HTTP_USER_AGENT'])) {
    	$userAgents = array("Google", "Slurp", "MSNBot", "ia_archiver", "Yandex", "Rambler","AbachoBOT","Acoon","AESOP_com_SpiderMan","ah-ha.com crawler","appie","Arachnoidea","ArchitextSpider","Atomz","DeepIndex","ESISmartSpider","EZResult","FAST-WebCrawler","Fido","Fluffy the spider","Gigabot","Gulliver","Gulper","HenryTheMiragoRobot","KIT-Fireball/2.0","LNSpiderguy","Lycos_Spider_(T-Rex)","MantraAgent","MSN","NationalDirectory-SuperSpider","Openfind piranha","Shark","Scooter","Scrubby","Tarantula","Teoma_agent1"," UK Searcher Spider","WebCrawler","Winona","ZyBorg","Cyveillance","Almaden","Openbot","Nazilla");
    	if(preg_match('/' . implode('|', $userAgents) . '/i', $_SERVER['HTTP_USER_AGENT'])) {
 		return true;
    	}
    	else{
    		return true;
       	}
	}
	}
    /*
    Anti SQL injection
    Return filtered String  
    */
    public static function SQLinj($valeur)
    {
        $valeur = addslashes($valeur);
        $valeur = htmlentities($valeur,ENT_QUOTES);
        return mysqli_real_escape_string($valeur);
    }
    /*
    Anti Cross Site Scripting
    Return filtered String  
    */
    public static function XSS($valeur)
    {
        
        $valeur = strip_tags($valeur);
        $valeur = htmlentities($valeur, ENT_QUOTES);
        $valeur = htmlspecialchars($valeur);
        if (get_magic_quotes_gpc()) {
            $valeur = stripslashes($valeur);
        }
        return $valeur;
    }
    /*
    Anti Remote File Inclusion 
    Return filtered String  
    */
    public static function RFI($valeur)
    {
        
        $valeur = str_replace("http://","",$valeur);
        $valeur = str_replace("https://","",$valeur);
        $valeur = str_replace("ftp://","",$valeur);
        $valeur = str_replace("php://","",$valeur);
        $valeur = str_replace("data://","",$valeur);
        $valeur = str_replace("base64","",$valeur);
        $valeur = str_replace("text","",$valeur);
        $valeur = str_replace("com://","",$valeur);
        $valeur = str_replace("://","",$valeur);
        
        return $valeur;
        
    }
    /* 
    Anti Local File Inclusion 
    Return filtered String  
    */
    public static function LFI($valeur)
    {
        $valeur = str_replace("%00","",$valeur);
        $valeur = str_replace("../","",$valeur);
        $valeur = str_replace("/passwd","",$valeur);
        $valeur = str_replace("/shadow","",$valeur);
        $valeur = str_replace("hosts","",$valeur);
        $valeur = str_replace("/etc/","",$valeur);
        $valeur = str_replace("config","",$valeur);
        return $valeur;
    }
    /*
    Helper Method For Tor Detecting
    */
    private function _IsTorExitPoint(){
        if (gethostbyname(_ReverseIPOctets($_SERVER['REMOTE_ADDR']).".".$_SERVER['SERVER_PORT']."."._ReverseIPOctets($_SERVER['SERVER_ADDR']).".ip-port.exitlist.torproject.org")=="127.0.0.2") {
            return true;
        } else {
            return false;
        }
    }
    private function _ReverseIPOctets($inputip){
        $ipoc = explode(".",$inputip);
        return $ipoc[3].".".$ipoc[2].".".$ipoc[1].".".$ipoc[0];
    }
    // END CLASS
}
?>
