# php-JSONWebToken

Simplifiación de la implementación de JSON Web Token, basada en la especificación https://tools.ietf.org/html/rfc7519 realizada por Neuman Vong y Anant Narayanan

 PHP requerido: version 5 o superior
 
 @category    Autenticación
 
 @package     UI1\Auth
 
 @author      trystan4861
 
 @license     https://github.com/Trystan4861/php-JSONWebToken/blob/main/LICENSE 3-clause BSD

 @version     v1.0
************************************************************************************

## Modo de Uso: 
      require_once("PATH2CLASS/class.ui1.jwt.inc.php");
      use UI1\Auth\JWT;
      
      Encriptar:
          JWT::encrypt(array $data[, integer $lifetimeInSeconds[,string $secretKeyRSA]]):returns string;

      Desencriptar:
          JWT::decrypt(string $token[, string $secretKeyRSA]):returns array;

### Modificadores de tiempo:
      Para poder hacer uso de los modificadores de tiempo de «no uso antes de» y de «caducidad» 
      se ha de incluir sendos par de clave => valor en el cuerpo de los datos a encriptar siendo 
      estos mpc_notbeforetimestamp y mpc_expirestimestamp respectivamente.

#### Ejemplo:
      JWT::encrypt(["clave1"=>"valor1",...,"mpc_notbeforetimestamp"=>1672531200, "mpc_expirestimestamp"=>1673049600]);
      
**Estableciendo que no se podrá usar el token antes de las 0:00:00 del domingo 1 de enero de 2023 hora GMT y caducará pasadas las 0:00:00 del sábado 7 de enero de 2023 hora GMT**

## Registro de cambios:

* 2023-01-25   Añadido «tiempo de gracia» a la vida útil del token y tiempos de «no válido antes de» y de «caducidad»
* 2023-01-24   Primera versión funcional.
* 2023-01-22   Reducción y limpieza de código no útil, limitando la funcionalidad de la clase original a los  procedimientos usados normalmente.
