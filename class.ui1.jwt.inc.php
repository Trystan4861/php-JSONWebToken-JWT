<?php
namespace UI1\Auth;

use DomainException;
use InvalidArgumentException;
use UnexpectedValueException;
use DateTime;

class BeforeValidException extends UnexpectedValueException{}
class ExpiredException extends UnexpectedValueException{}
class SignatureInvalidException extends UnexpectedValueException{}


/**
 * Simplifiación de la implementación de JSON Web Token, basada en la especificación
 * https://tools.ietf.org/html/rfc7519 realizada por Neuman Vong y Anant Narayanan
 *
 * PHP requerido: version 5 o superior
 * 
 * @category    Autenticación
 * @package     UI1\Auth
 * @author      trystan4861
 * @license     https://github.com/Trystan4861/php-JSONWebToken/blob/main/LICENSE 3-clause BSD
 *
 * @version     v1.0
 *
 ************************************************************************************
 *
 * HOWTO: 
 *      require_once("PATH2CLASS/class.ui1.jwt.inc.php");
 *      use UI1\Auth\JWT;
 *      
 *      Encriptar:
 *          JWT::encrypt(array $data[, integer $lifetimeInSeconds[,string $secretKeyRSA]]):returns string;
 *
 *      Desencriptar:
 *          JWT::decrypt(string $token[, string $secretKeyRSA]):returns array;
 *
 * Registro de cambios:
 * 
 * 2023-01-25   Añadido «tiempo de gracia» a la vida útil del token y tiempos de «no válido antes de» y de «caducidad»
 * 2023-01-24   Primera versión funcional.
 * 2023-01-22   Reducción y limpieza de código no útil, limitando la funcionalidad de la clase original a los 
 *              procedimientos usados normalmente.
 */
class JWT
{

    private static $tiempoDGracia=0;
    private static $secret_key = <<<MPC
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgFIYl1l8UP8t/OrYDRzzkyKMdnRHgNM+ql8UxzW01WBaz9l6SzRz
LI0tg1CX0Su3pdQg0zDSk1Ybz+PTYf6d4M5qpMW3TlinKz1QJLB6qasKjxoRfIVI
ahv8axojH94w9Un3GTmpfJoXUPuJjE3CPdhnYvFk34ZtHuyvT1GE4JfFAgMBAAEC
gYAqs8Hd+Q0Efr5ExZakjYnl+ZwPxbWbq8fg5yTrqaEnmnTs0XDW2mW9FYRtYlqZ
28+09FIF3jJnItZS0fvx/dsVzI+jC4CZNLfho/tGge44fdtIDQfsUEQjY61eGvo8
WlFuPxAzZjoaI4zAWBSA62dYDg/RzWrLE5FiempOfm3YLQJBAJG6wHHBtCgEeerP
r9d4m8FDdviBPrySqcYB3iANOPueR1rPxUYU5ZunlUX/zg8xO07LLUkp7UqhyFm9
gMzD2e8CQQCQN2lcUlbKd1FUyec1OIlIHFGfNglsRlKe0i1nJxtgsBRDILXz522b
zeXNo6qac+3tkgWouwYmru5mlK9Jqe2LAkBztDULnOIvS66I8rEIgSgZQDl7gRKQ
olnNbrov9I+jp727qm9U/052UY5Bb6LpiQsvuj2Qc4uF0AHEzqMu8OldAkBJBuYh
S8iLKbRTfRHJD2Hk1AI43sISw+FebwtyqojggwkfnNbGNTB5rt9pLDFdmMqofELF
WD8bI4WxCCVi5dtVAkEAjXqYJidZXclGmn0+X39rB79ejyYDcab/UZFuMn7iNx3U
SNYJIvAymqfyGgHonBQqf8aLMaXQww01l6udDPVyBw==
-----END RSA PRIVATE KEY-----
MPC;

    private static $messages = array(
        JSON_ERROR_DEPTH => 'Profundidad máxima de pila excedida',
        JSON_ERROR_STATE_MISMATCH => 'JSON no válido o mal formado',
        JSON_ERROR_CTRL_CHAR => 'Encontrado caracter de control inesperado',
        JSON_ERROR_SYNTAX => 'Error de sintaxis, JSON mal formado',
        JSON_ERROR_UTF8 => 'Caracteres UTF-8 mal formados'
    );

    /**
     * Convierte y firma un objeto o array PHP en una cadena JWT.
     *
     * @param object|array  $data               El objeto o el array PHP 
     * @param integer       $lifetimeInSeconds  El tiempo de vida de la cadena firmada
     * @param string        $secret_key         La clave secreta.
     *
     * @return string                           Una cadena JWT firmada
     *
     * @uses doEncode
     */
    public static function encrypt($data,$lifetime=3600,$secret_key=null)
    {
        return self::doEncode(array('exp' => (time() + $lifetime),'aud' => self::Aud(),'data' => $data),is_null($secret_key)?self::$secret_key:$secret_key);
    }
    /**
     * Decodifica una cadena JWT en un objeto PHP.
     *
     * @param string                $token          La cadena JWT
     * @param string|array|resource $secret_key     La clave o mapa de claves.
     * @return object                       The JWT's payload as a PHP object
     *
     * @throws UnexpectedValueException     La cadena JWT suministrada no es válida
     * @throws SignatureInvalidException    La cadena JWT suministrada no es válida porque la verificación de la firma falló
     * @throws BeforeValidException         La cadena JWT suministrada se está tratando de usar antes de su fecha de uso eligible definido en 'nbf'
     * @throws BeforeValidException         La cadena JWT suministrada se está tratando de usar antes de su fecha de creación definida en 'iat'
     * @throws ExpiredException             La cadena JWT suministrada ha expirado, como fue definido en 'exp'
     *
     * @uses doDecode
     */
    public static function decrypt($token,$secret_key=null)
    {
        if (is_null($secret_key)) $secret_key=self::$secret_key;
        try
        {
                $data= self::doDecode($token,$secret_key)->data;
        }
        catch (Exception $e)
        {
            $data["error"]=$e->getMessage();
            $data=json_decode(json_encode($data), FALSE);
        }
        return $data;
    }
    /**
     * Establece el tiempo de gracia que se le añadirá a la vida útil del token
     * @param integer $tiempo       tiempo en segundos
     */
    public static function setMargenDeGracia(int $tiempo)
    {
        if ($tiempo<=0) return;
        static::$tiempoDGracia=$tiempo;
    }
    /**
     * Obtiene el tiempo de gracia asignado al token
     * @return integer              tiempo de gracia que se le añade a la vida útil del token
     */
    public static function getMargenDeGracia()
    {
        return static::$tiempoDGracia;
    }
    /**
     * Establece la clave secreta por defecto a ser usada durante la vida de la clase
     * @param string $secret_key la clave secreta RSA a establecer
     */
    public static function setRSASecretKey(string $secret_key)
    {
        static::$secret_key=$secret_key;
    }
    private static function doDecode($jwt, $key)
    {
        $timestamp = time();

        $segmentos = explode('.', $jwt);
        if (count($segmentos) != 3) throw new UnexpectedValueException('Número de segmentos erróneo');
        list($headB64, $bodyB64, $cryptoB64) = $segmentos;

        if (null === ($header = static::jsonDecode(static::urlsafeB64Decode($headB64)))) throw new UnexpectedValueException('Codificación de cabecera no válida');
        if (null === $payload = static::jsonDecode(static::urlsafeB64Decode($bodyB64))) throw new UnexpectedValueException('Codificación de contenido no válida');
        if (false === ($sig = static::urlsafeB64Decode($cryptoB64)))  throw new UnexpectedValueException('Codificación de firma no válida');

        if (!static::verify("$headB64.$bodyB64", $sig, $key))  throw new SignatureInvalidException('Error en la verificación de la firma');
        if (isset($payload->mpc_notbeforetimestamp) && $payload->mpc_notbeforetimestamp > ($timestamp + static::$tiempoDGracia)) throw new BeforeValidException('Este token no puede ser usado antes de '.date(DateTime::ISO8601, $payload->mpc_notbeforetimestamp));
        if (isset($payload->mpc_expirestimestamp) && ($timestamp - static::$tiempoDGracia) >= $payload->mpc_expirestimestamp) throw new ExpiredException('El token caducó el '.date(DateTime::ISO8601, $payload->mpc_expirestimestamp));

        return $payload;
    }

    private static function doEncode($payload, $key)
    {
        $header = array('tipo' => 'JWT');

        $segments = array();
        $segments[] = static::urlsafeB64Encode(static::jsonEncode($header));
        $segments[] = static::urlsafeB64Encode(static::jsonEncode($payload));
        $signing_input = implode('.', $segments);

        $signature = static::sign($signing_input, $key);
        $segments[] = static::urlsafeB64Encode($signature);

        return implode('.', $segments);
    }

    private static function sign($msg, $key){return hash_hmac("SHA256", $msg, $key, true);}

    private static function verify($msg, $signature, $key)
    {
        $hash = hash_hmac("SHA256", $msg, $key, true);
        if (function_exists('hash_equals')) return hash_equals($signature, $hash);

        $len = min(static::safeStrlen($signature), static::safeStrlen($hash));

        $status = 0;
        for ($i = 0; $i < $len; $i++)
            $status |= (ord($signature[$i]) ^ ord($hash[$i]));
        
        $status |= (static::safeStrlen($signature) ^ static::safeStrlen($hash));

        return ($status === 0);
    }

    private static function jsonDecode($input)
    {
        if (version_compare(PHP_VERSION, '5.4.0', '>=') && !(defined('JSON_C_VERSION') && PHP_INT_SIZE > 4))  $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);
        else
        {
            $max_int_length = strlen((string) PHP_INT_MAX) - 1;
            $json_without_bigints = preg_replace('/:\s*(-?\d{'.$max_int_length.',})/', ': "$1"', $input);
            $obj = json_decode($json_without_bigints);
        }

        if ($errno = json_last_error()) static::handleJsonError($errno);
        elseif ($obj === null && $input !== 'null') throw new DomainException('Resultado nulo con entrada no nula');
        return $obj;
    }

    private static function jsonEncode($input)
    {
        $json = json_encode($input);
        if ($errno = json_last_error()) static::handleJsonError($errno);
        elseif ($json === 'null' && $input !== null) throw new DomainException('Resultado nulo con entrada no nula');
        return $json;
    }

    private static function urlsafeB64Decode($input)
    {
        $remainder = strlen($input) % 4;
        if ($remainder) $input .= str_repeat('=', 4 - $remainder);
        return base64_decode(strtr($input, '-_', '+/'));
    }

    private static function urlsafeB64Encode($txt){return str_replace('=','',strtr(base64_encode($txt),'+/','-_'));}

    private static function handleJsonError($errno){throw new DomainException(isset(static::$messages[$errno])?static::$messages[$errno]:'Error JSON desconocido: '.$errno);}

    private static function safeStrlen($str)
    {
        if (function_exists('mb_strlen')) return mb_strlen($str, '8bit');
        return strlen($str);
    }

    public static function Aud()
    {
        $aud = '';

        if (!empty($_SERVER['HTTP_CLIENT_IP'])) $aud = $_SERVER['HTTP_CLIENT_IP'];
        elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) $aud = $_SERVER['HTTP_X_FORWARDED_FOR'];
        else $aud = $_SERVER['REMOTE_ADDR'];

        $aud .= @$_SERVER['HTTP_USER_AGENT'];
        $aud .= gethostname();

        return sha1($aud);
    }

}
?>