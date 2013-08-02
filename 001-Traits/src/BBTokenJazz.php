<?PHP



abstract class Security 
{

    protected $cipherName = MCRYPT_RIJNDAEL_256; 
    protected $mode = MCRYPT_MODE_CBC; 

    // these encrypt/decrypt functions are jacked from: http://www.php.net/manual/es/book.mcrypt.php#107483
    public function encrypt($decrypted, $salt)
    { 

        $dto = new DateTime();
        $dto->modify('+5 minutes');
        $decrypted .= sprintf(":%s", $dto->format("U"));

        $key = hash('SHA256', $salt, true);
        srand(); 
        $iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC), MCRYPT_RAND);

        if (strlen($iv_base64 = rtrim(base64_encode($iv), '=')) != 22) {
            return false;
        }
        $encrypted = base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $decrypted . md5($decrypted), MCRYPT_MODE_CBC, $iv));
        
        return $iv_base64 . $encrypted;
    } 

    public function decrypt($encrypted, $salt) 
    {
        $key = hash('SHA256', $salt, true);
        $iv = base64_decode(substr($encrypted, 0, 22) . '==');
        
        $encrypted = substr($encrypted, 22);
        $decrypted = rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, base64_decode($encrypted), MCRYPT_MODE_CBC, $iv), "\0\4");
       
        $hash = substr($decrypted, -32);
        $decrypted = substr($decrypted, 0, -32);

        if (md5($decrypted) != $hash) {
        
            return false;
        }
        
        return $decrypted;
    }

} // security class

class BlackBird extends Security 
{
    private $token;  // hashed token
    private $username; // BB doesn't need the uname but it adds to difficulty of token hash
    private $expiryTime; // time when this token expires

    public function setToken($token)
    {
      $this->token = $token;
    }

    public function isValid()
    {
      list($this->username, $this->expiryTime) = explode(":", $this->decrypt($this->token, $this->getSalt()));
      $dto = new DateTime();
      return (bool) ($dto->format("U") < $this->expiryTime);

    }


} // BlackBird


class ExtraNet extends Security 
{
    private $username; // EN is already making use of the Username

    public function setUsername($username)
    {
        $this->username = $username;
    }

    public function getToken()
    {
        $token = $this->encrypt($this->username, $this->getSalt());

        return $token;
    }


} // ExtraNet


$en = new ExtraNet();
$bb = new BlackBird();
$en->setUsername("mbreedlove");
$token = $en->getToken();
$token2 = $en->getToken();
echo "http://imaging.qa.myfamc.com/micahTest/services/getUpload.php?transaction_id=20130501162220269&auth_token=" . $token .  "\n";
echo "\n\ntoken1: " .$token . "\ntoken2: " . $token2 . "\n";
echo "\n\ntoken1: " .strlen($token) . "\ntoken2: " . strlen($token2) . "\n";
$bb->setToken($token);
echo $bb->isValid();
