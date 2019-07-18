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

Description :  WebSecurity is a PHP class to Help Developper to prevent a almost webapplication security fails:
			   
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
        return _IsTorExitPoint();
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
    public static function SQLinj($value)
    {
        $value = addslashes($value);
        $value = htmlentities($value,ENT_QUOTES);
        return mysql_real_escape_string($value);
    }
    /*
    Anti Cross Site Scripting
    Return filtered String  
    */
    public static function XSS($value)
    {
        
        $value = strip_tags($value);
        $value = htmlentities($value, ENT_QUOTES);
        $value = htmlspecialchars($value);
        if (get_magic_quotes_gpc()) {
            $value = stripslashes($value);
        }
        return $value;
    }
    /*
    Anti Remote File Inclusion 
    Return filtered String  
    */
    public static function RFI($value)
    {
        
        $value = str_replace("http://","",$value);
        $value = str_replace("https://","",$value);
        $value = str_replace("ftp://","",$value);
        $value = str_replace("php://","",$value);
        $value = str_replace("data://","",$value);
        $value = str_replace("base64","",$value);
        $value = str_replace("text","",$value);
        $value = str_replace("com://","",$value);
        $value = str_replace("://","",$value);
        
        return $value;
        
    }
    /* 
    Anti Local File Inclusion 
    Return filtered String  
    */
    public static function LFI($value)
    {
        $value = str_replace("%00","",$value);
        $value = str_replace("../","",$value);
        $value = str_replace("/passwd","",$value);
        $value = str_replace("/shadow","",$value);
        $value = str_replace("hosts","",$value);
        $value = str_replace("/etc/","",$value);
        $value = str_replace("config","",$value);
        return $value;
    }
    /*
    Helper Method For Tor Detecting
    */
    private function _IsTorExitPoint(){
        return  (gethostbyname(_ReverseIPOctets($_SERVER['REMOTE_ADDR']).".".$_SERVER['SERVER_PORT']."."._ReverseIPOctets($_SERVER['SERVER_ADDR']).".ip-port.exitlist.torproject.org")=="127.0.0.2");
    }
    private function _ReverseIPOctets($inputip){
        $ipoc = explode(".",$inputip);
        return $ipoc[3].".".$ipoc[2].".".$ipoc[1].".".$ipoc[0];
    }
    // END CLASS
}
?>
