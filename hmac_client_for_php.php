<?php

class HMACClient {

	private $rootPath;
	private $key;
	private $secret;

	public function __construct($path, $key, $secret) {
		if (isset($secret) && isset($key))
		{
			$this->rootPath = $path;
			$this->key = $key;
			$this->secret = $secret;
		} else
			die("NO KEY/SECRET");
	}

	public function do_private_query($requestMethod, $requestUri, $body=null) {

		$requestUri = '/' . $requestUri;
		$url = $this->rootPath . $requestUri;

		// generate a nonce as microtime, with as-string handling to avoid problems with 32bits systems
		$mt = explode(' ', microtime());
		$nonce = $mt[1] . substr($mt[0], 2, 6);
		$nonce = 123;

		$json=null;
		if (isset($body)) {
			$json = json_encode($body);
		}

        $payload = '';
        $payload .= $requestMethod . "\n";
        $payload .= $requestUri . $theParam . "\n";
        $payload .= $nonce . "\n";
        $payload .= $json;

		$signature = $this->get_signature($payload);

        $headers = array('AUTHENTICATION: HMAC ' . $this->key . ':' . $signature . ':' . $nonce);

		// our curl handle (initialize if required)
		static $ch = null;
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_USERAGENT, 'Mozilla/4.0 (compatible; PHP client; ' . php_uname('s') . '; PHP/' . phpversion() . ')');

        curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $requestMethod);

		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1);  
		curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);  
		
		curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $json);

		// run the query
		$res = curl_exec($ch);
		$info = curl_getinfo($ch);	
		$info_json = json_encode($info);

		if ($res === false)
			throw new \Exception('Could not get reply: ' . curl_error($ch));
		return $res;
	}

	private function get_signature($payload) {
	  return hash_hmac('sha256', $payload, $this->secret);
	}
	
	function status() {
        $res = $this->do_private_query('GET', 'status', null);
        return $res;
	}

}

$path = "http://127.0.0.1:8000/api";
$key = 'NOV_KEY';
$secret = 'NOV_SECRET';
$client = new HMACClient($path, $key, $secret);

print_r($client->do_private_query('GET', 'status', null) . "\n");

?>