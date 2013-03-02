 <?php
   session_start();
   include_once("io.php"); //io operations for reading input to bytearrays and visa versa

   $_SESSION['debug'] = "";
   $_SESSION['input'] = htmlspecialchars(trim($_POST['input']));
   $_SESSION['key'] = htmlspecialchars(trim($_POST['key']));
   $_SESSION['format'] = htmlspecialchars(trim($_POST['format']));
   $_SESSION['source'] = $_SERVER['SCRIPT_FILENAME'];
   $operation = htmlspecialchars(trim($_POST['operation']));

   $iop = new ioOperations();
   //create byte array from string key
   $key = $iop->getByteArrayFromKeyString();
   //create byte array from user's input   
   $bytearray = $iop->getByteArrayFromInput();
   if (empty($bytearray)) $_SESSION['debug'] .= "\ninput not valid";
   else
   {
      //create AES state (4x4 bytes) of byte array
      $state = $iop->getState($bytearray);
      //put key in 4x4 byte array too
      //$key = $iop->getState($keyarray);
   
      // perform a subBytes operation
      $aesops = new Aes();
      $result = array();
      $_SESSION['debug'] .= "\nThe ". $operation . " operation:\n";
      switch ($operation){
         case "subBytes":
            $result=$aesops->subBytes($state);
            break;
         case "shiftRows":
            $result=$aesops->shiftRows($state);
            break;
         case "mixColumns":
            $result=$aesops->mixColumns($state);
            break;
         case "addRoundKey":
            $w = $aesops->keyExpansion($key); //generate roundkeys in key expansion 
            $result=$aesops->addRoundKey($state, $w, 0); //add roundkey 0 for this example
            break;
         case "encrypt":
            $result=$aesops->encrypt($state);
            break;
         case "decrypt":
            $result=$aesops->decrypt($state);
            break;
         default:
            $_SESSION['debug'] .= "\n Error, operation not valid";
      }
            

      // now convert back the final state to output 
      $output = $iop->convertStateToByteArray($result);
      $_SESSION['debug'] .= "\n\nThe hexadecimal result of the ". $operation ." operation:\n$output\n";
      $_SESSION['output'] = $output;
   }   
   header('Location:operations.php'); //reload the operations.php page with the session values
?>


<?php
/*
 * This is the class section of this php file.
 * It defines two classes AesSubbytes and ioOperations
 */ 
   class Aes {

      /**
       *  This class implements onse part of the AES algortihm, the subBytes operation.
       *  It is meant for demonstration purpose only.
      **/
       
      // sBox is the pre-computed multiplicative inverse in GF(2^8) used in subBytes() and also in the keyExpansion.
      private static $sBox = array(
      0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
      0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
      0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
      0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
      0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
      0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
      0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
      0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
      0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
      0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
      0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
      0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
      0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
      0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
      0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
      0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16);

      // rCon is Round Constant used for the Key Expansion, first column is 2^(r-1) in GF(2^8)
      private static $rCon = array( 
      array(0x00, 0x00, 0x00, 0x00),
      array(0x01, 0x00, 0x00, 0x00),
      array(0x02, 0x00, 0x00, 0x00),
      array(0x04, 0x00, 0x00, 0x00),
      array(0x08, 0x00, 0x00, 0x00),
      array(0x10, 0x00, 0x00, 0x00),
      array(0x20, 0x00, 0x00, 0x00),
      array(0x40, 0x00, 0x00, 0x00),
      array(0x80, 0x00, 0x00, 0x00),
      array(0x1b, 0x00, 0x00, 0x00),
      array(0x36, 0x00, 0x00, 0x00) ); 


      public function encrypt($input)
      {
         $_SESSION['debug'] .= "^^^^^^^^^^^^^^^^^^^^^^^^^^^\nEncryptie van een blok data is \nnog niet geimplementeerd, \nzie opdrachten studiewijzer\n^^^^^^^^^^^^^^^^^^^^^^^^^^^\n";
         return($input);
      } //end function encrypt

      public function decrypt($input)
      {
         $_SESSION['debug'] .= "^^^^^^^^^^^^^^^^^^^^^^^^^^^\nDecryptie van een blok data is \nnog niet geimplementeerd, \nzie opdrachten studiewijzer\n^^^^^^^^^^^^^^^^^^^^^^^^^^^\n";
         return($input);
      } //end function decrypt

      public function subBytes($state)
      {
         for ($row=0; $row<4; $row++){ // for all 16 bytes in the (4x4-byte) State
            for ($column=0; $column<4; $column++){ // for all 16 bytes in the (4x4-byte) State
               $_SESSION['debug'] .= "state[$row][$column]=" . $state[$row][$column] .
                  "-->" . self::$sBox[$state[$row][$column]]."\n";
               $state[$row][$column] = self::$sBox[$state[$row][$column]];
            }
         }
         return $state;
      } // end function subBytes

      public function shiftRows($state)
      {
         $temp = array(); //create temporary array for shifting
         for ($row=0; $row<4; $row++){ 
            for ($column=0; $column<4; $column++){ 
               //shiftleft the rows n positions for row n, so 0 for row 0, 1 position for row 1, etc.
               $temp[$row][$column] = $state[$row][($column+$row)%4];  
            }
         }

         //now, copy back the result from temp to state
         for ($row=0; $row<4; $row++){ 
            for ($column=0; $column<4; $column++){ 
               $state[$row][$column] = $temp[$row][$column];
               $_SESSION['debug'] .= "state[$row][$column]=".$state[$row][$column]."\n";
            }
         }         
         return $state;
      } // end function shiftRows


      public static function mixColumns($state)
      {  
         //multiplication tables  taken from http://en.wikipedia.org/wiki/Rijndael_mix_columns
         static $mul2 = array(
            0x00,0x02,0x04,0x06,0x08,0x0a,0x0c,0x0e,0x10,0x12,0x14,0x16,0x18,0x1a,0x1c,0x1e,
            0x20,0x22,0x24,0x26,0x28,0x2a,0x2c,0x2e,0x30,0x32,0x34,0x36,0x38,0x3a,0x3c,0x3e,
            0x40,0x42,0x44,0x46,0x48,0x4a,0x4c,0x4e,0x50,0x52,0x54,0x56,0x58,0x5a,0x5c,0x5e,
            0x60,0x62,0x64,0x66,0x68,0x6a,0x6c,0x6e,0x70,0x72,0x74,0x76,0x78,0x7a,0x7c,0x7e,
            0x80,0x82,0x84,0x86,0x88,0x8a,0x8c,0x8e,0x90,0x92,0x94,0x96,0x98,0x9a,0x9c,0x9e,
            0xa0,0xa2,0xa4,0xa6,0xa8,0xaa,0xac,0xae,0xb0,0xb2,0xb4,0xb6,0xb8,0xba,0xbc,0xbe,
            0xc0,0xc2,0xc4,0xc6,0xc8,0xca,0xcc,0xce,0xd0,0xd2,0xd4,0xd6,0xd8,0xda,0xdc,0xde,
            0xe0,0xe2,0xe4,0xe6,0xe8,0xea,0xec,0xee,0xf0,0xf2,0xf4,0xf6,0xf8,0xfa,0xfc,0xfe,
            0x1b,0x19,0x1f,0x1d,0x13,0x11,0x17,0x15,0x0b,0x09,0x0f,0x0d,0x03,0x01,0x07,0x05,
            0x3b,0x39,0x3f,0x3d,0x33,0x31,0x37,0x35,0x2b,0x29,0x2f,0x2d,0x23,0x21,0x27,0x25,
            0x5b,0x59,0x5f,0x5d,0x53,0x51,0x57,0x55,0x4b,0x49,0x4f,0x4d,0x43,0x41,0x47,0x45,
            0x7b,0x79,0x7f,0x7d,0x73,0x71,0x77,0x75,0x6b,0x69,0x6f,0x6d,0x63,0x61,0x67,0x65,
            0x9b,0x99,0x9f,0x9d,0x93,0x91,0x97,0x95,0x8b,0x89,0x8f,0x8d,0x83,0x81,0x87,0x85,
            0xbb,0xb9,0xbf,0xbd,0xb3,0xb1,0xb7,0xb5,0xab,0xa9,0xaf,0xad,0xa3,0xa1,0xa7,0xa5,
            0xdb,0xd9,0xdf,0xdd,0xd3,0xd1,0xd7,0xd5,0xcb,0xc9,0xcf,0xcd,0xc3,0xc1,0xc7,0xc5,
            0xfb,0xf9,0xff,0xfd,0xf3,0xf1,0xf7,0xf5,0xeb,0xe9,0xef,0xed,0xe3,0xe1,0xe7,0xe5);

         static $mul3 = array(
            0x00,0x03,0x06,0x05,0x0c,0x0f,0x0a,0x09,0x18,0x1b,0x1e,0x1d,0x14,0x17,0x12,0x11,
            0x30,0x33,0x36,0x35,0x3c,0x3f,0x3a,0x39,0x28,0x2b,0x2e,0x2d,0x24,0x27,0x22,0x21,
            0x60,0x63,0x66,0x65,0x6c,0x6f,0x6a,0x69,0x78,0x7b,0x7e,0x7d,0x74,0x77,0x72,0x71,
            0x50,0x53,0x56,0x55,0x5c,0x5f,0x5a,0x59,0x48,0x4b,0x4e,0x4d,0x44,0x47,0x42,0x41,
            0xc0,0xc3,0xc6,0xc5,0xcc,0xcf,0xca,0xc9,0xd8,0xdb,0xde,0xdd,0xd4,0xd7,0xd2,0xd1,
            0xf0,0xf3,0xf6,0xf5,0xfc,0xff,0xfa,0xf9,0xe8,0xeb,0xee,0xed,0xe4,0xe7,0xe2,0xe1,
            0xa0,0xa3,0xa6,0xa5,0xac,0xaf,0xaa,0xa9,0xb8,0xbb,0xbe,0xbd,0xb4,0xb7,0xb2,0xb1,
            0x90,0x93,0x96,0x95,0x9c,0x9f,0x9a,0x99,0x88,0x8b,0x8e,0x8d,0x84,0x87,0x82,0x81,
            0x9b,0x98,0x9d,0x9e,0x97,0x94,0x91,0x92,0x83,0x80,0x85,0x86,0x8f,0x8c,0x89,0x8a,
            0xab,0xa8,0xad,0xae,0xa7,0xa4,0xa1,0xa2,0xb3,0xb0,0xb5,0xb6,0xbf,0xbc,0xb9,0xba,
            0xfb,0xf8,0xfd,0xfe,0xf7,0xf4,0xf1,0xf2,0xe3,0xe0,0xe5,0xe6,0xef,0xec,0xe9,0xea,
            0xcb,0xc8,0xcd,0xce,0xc7,0xc4,0xc1,0xc2,0xd3,0xd0,0xd5,0xd6,0xdf,0xdc,0xd9,0xda,
            0x5b,0x58,0x5d,0x5e,0x57,0x54,0x51,0x52,0x43,0x40,0x45,0x46,0x4f,0x4c,0x49,0x4a,
            0x6b,0x68,0x6d,0x6e,0x67,0x64,0x61,0x62,0x73,0x70,0x75,0x76,0x7f,0x7c,0x79,0x7a,
            0x3b,0x38,0x3d,0x3e,0x37,0x34,0x31,0x32,0x23,0x20,0x25,0x26,0x2f,0x2c,0x29,0x2a,
            0x0b,0x08,0x0d,0x0e,0x07,0x04,0x01,0x02,0x13,0x10,0x15,0x16,0x1f,0x1c,0x19,0x1a);


         for ($c=0; $c<4; $c++) {
            $a = array(4);  // 'a' is a copy of the current column from 's'           
            for ($i=0; $i<4; $i++) $a[$i] = $state[$i][$c]; 
            
            $_SESSION['debug'] .= "\na is copy column from state: " . implode(",", $a);
            $state[0][$c] = $mul2[$a[0]] ^ $mul3[$a[1]] ^ $a[2] ^ $a[3]; // 2*a0 + 3*a1 + a2 + a3
            $state[1][$c] = $a[0] ^ $mul2[$a[1]] ^ $mul3[$a[2]] ^ $a[3]; // a0 * 2*a1 + 3*a2 + a3
            $state[2][$c] = $a[0] ^ $a[1] ^ $mul2[$a[2]] ^ $mul3[$a[3]]; // a0 + a1 + 2*a2 + 3*a3
            $state[3][$c] = $mul3[$a[0]] ^ $a[1] ^ $a[2] ^ $mul2[$a[3]]; // 3*a0 + a1 + a2 + 2*a3

            $_SESSION['debug'] .= "\nresulting column: ".$state[0][$c].",".$state[1][$c].",".$state[2][$c].",".$state[3][$c];            
         }
         return $state;
      } // end function mixColumns


      public function addRoundKey($state, $w, $rnd)   // xor Round Key into state S [�5.1.4]
      {
         $_SESSION['debug'] .= "\naddRoundKey:\n";
         for ($r=0; $r<4; $r++) {
            for ($c=0; $c<4; $c++){
               $_SESSION['debug'] .= "state[".$r."][".$c."]=".$state[$r][$c]." XOR ".$w[$rnd*4+$c][$r]."=";
               $state[$r][$c] ^= $w[$rnd*4+$c][$r];
               $_SESSION['debug'] .= $state[$r][$c]."\n";
            }
         }
         return $state;
      } // end function addRoundKey


      public static function keyExpansion($key)   // generate Key Schedule from Key
      {
         $_SESSION['debug'] .= "keyExpansion:\n";
         $Nk = count($key)/4;  // key length (in words): 4/6/8 for 128/192/256-bit keys
         $Nr = $Nk + 6;        // no of rounds: 10/12/14 for 128/192/256-bit keys
  
         $w = array();
         $temp = array();
         $_SESSION['debug'] .= "key[0]=";
         for ($i=0; $i<$Nk; $i++) {
            $r = array($key[4*$i], $key[4*$i+1], $key[4*$i+2], $key[4*$i+3]);
            $w[$i] = $r;
            //$_SESSION['debug'] .= "w[".$i."]=";
            for ($n=0; $n<4; $n++) $_SESSION['debug'] .= dechex($w[$i][$n])." ";            
         }
         $_SESSION['debug'] .= "\nkey[1]=";
         for ($i=$Nk; $i<(4*($Nr+1)); $i++) {
            $w[$i] = array();
            for ($t=0; $t<4; $t++) $temp[$t] = $w[$i-1][$t];
            if ($i % $Nk == 0) {
              $temp = self::subWord(self::rotWord($temp));
            for ($t=0; $t<4; $t++) $temp[$t] ^= self::$rCon[$i/$Nk][$t];
            } else if ($Nk > 6 && $i%$Nk == 4) {
            $temp = self::subWord($temp);
            }
            //$_SESSION['debug'] .= "w[".$i."]=";
            for ($t=0; $t<4; $t++) {
               $w[$i][$t] = $w[$i-$Nk][$t] ^ $temp[$t];
               $_SESSION['debug'] .= dechex($w[$i][$t])." ";
            }
            if (((($i+1)%4)==0)&&($i<4*$Nr)) $_SESSION['debug'] .= "\nkey[".(($i+1)/4)."]=";           
         }
         return $w;
      }// end function keyExpansion


      private static function subWord($w) // apply SBox to 4-byte word w
      {
         for ($i=0; $i<4; $i++) $w[$i] = self::$sBox[$w[$i]];
         return $w;
      }
  
      private static function rotWord($w) // rotate 4-byte word w left by one byte
      {
         $tmp = $w[0];
         for ($i=0; $i<3; $i++) $w[$i] = $w[$i+1];
         $w[3] = $tmp;
         return $w;
      }
      
   } //end class AesSubBytes

?>


<?php
   class ioOperations {
      /**
       *  This class implements several different operations on input
       *  It has functions to convert form input to a byte array and 
       *  to convert a byte array to a state (as defined in AES)
      **/

      public function getByteArrayFromKeyString()
      {  $correct = false;
         $retv = "";
      
         $in = htmlspecialchars(trim($_POST['key']));

         if ( (!isset($in)) || ($in === NULL) ) {
         $_SESSION['debug'] .= "input not correct";
         }
         else if (empty($in)){
            $_SESSION['debug'] .= "key is empty";
         }
         else {
               //removing spaces and 0x hex format specifiers is not fool-proof but gets normal input to  hex format
               $in = str_replace(' ', '', $in); //remove all spaces from string
               $in = str_replace('\x', '', $in); // remove all 0x hex format specifiers
               $in = str_replace('0x', '', $in); // remove all 0x hex format specifiers
               $index = 0;
               for ($i=0; $i<strlen($in); $i+=2) {
                  $ss = substr($in, $i, 2);
                  $bytearray[$index] = hexdec($ss);
                  //$bytearray[$index] = $ss;
                  $index++;
               }   
               
               for ($i=$index; $i<16; $i++) $bytearray[$i] = 0;
   
               $_SESSION['debug'] .= "The key string converted to a byte-array with the decimal representation of the keybytes:";
               $_SESSION['debug'] .= "\n". implode(",", $bytearray) ."\n";
               $retv = $bytearray;
               $correct = true;
         }
                  
         if ($correct){
            return $retv;
         }
         else{
            return "";
         }
      }
      
      public function getByteArrayFromInput()
      {  $correct = false;
         $retv = "";
      
         $in = htmlspecialchars(trim($_POST['input']));
         $operation = htmlspecialchars(trim($_POST['operation']));

         if ( (!isset($in)) || ($in === NULL) ) {
         $_SESSION['debug'] .= "input not correct";
         }
         else if (empty($in)){
            $_SESSION['debug'] .= "Input is empty";
         }
         else if (!(($_POST['format']=='ascii') || ($_POST['format']=='hex'))){
            $_SESSION['debug'] .= "format incorrect";
         }
         else if (!(($_POST['operation']=='subBytes') || ($_POST['operation']=='shiftRows') || ($_POST['operation']=='mixColumns') || ($_POST['operation']=='addRoundKey') 
                    || ($_POST['operation']=='encrypt') || ($_POST['operation']=='decrypt') )){
            $_SESSION['debug'] .= "operation not supported";
         }
         else {
            if ($_POST['format']=='ascii'){
               if(strlen($in) > 16){
                  $_SESSION['debug'] .= "input to long, maximum length is 16 bytes";
               }
               else
               {
                  //read posted data for state data and for data-format (ascii or hex)

                  // convert to a decimal representation of the ascii-values, C for unsigned char
                  $bytearray = unpack('C*', $in); 

                  // make bytearray start at index 0, because result from unpack starts at index 1
                  $bytearray = array_merge($bytearray); 
                  if (strlen($in)<16){ //pad with null values
                     for ($i=strlen($in); $i<16; $i++) $bytearray[$i] = 0;
                  }
   
                  $_SESSION['debug'] .= "The input converted to a byte-array with the decimal representation of the ascii-values:";
                  $_SESSION['debug'] .= "\n". implode(",", $bytearray) ."\n";
                  $retv = $bytearray;
                  $correct = true;
               }
            }
            else if ($_POST['format']=='hex'){
               //$_SESSION['debug'] .= "\nhex format not supported yet, sorry!";
               //removing spaces and 0x hex format specifiers is not fool-proof but gets normal input to just hex numbers
               $in = str_replace(' ', '', $in); //remove all spaces from string
               $in = str_replace('\x', '', $in); // remove all 0x hex format specifiers
               $in = str_replace('0x', '', $in); // remove all 0x hex format specifiers
               $index = 0;
               for ($i=0; $i<strlen($in); $i+=2) {
                  $ss = substr($in, $i, 2);
                  //$array = unpack("H*data", $ss);
                  //$answer = $array["data"];
                  $bytearray[$index] = hexdec($ss);
                  $index++;
               }   
               
               for ($i=$index; $i<16; $i++) $bytearray[$i] = 0;
   
               $_SESSION['debug'] .= "The input converted to a byte-array with the decimal representation of the ascii-values:";
               $_SESSION['debug'] .= "\n". implode(",", $bytearray) ."\n";
               $retv = $bytearray;
               $correct = true;
            }
         }
                  
         if ($correct){
            return $retv;
         }
         else{
            return "";
         }
      }

   
      public function getState($bytearray)
      {
         // let's convert the input to the state as done with the AES-input, 
         // so first input-byte goes to state[0][0], second input-byte goes to state[1][0], etc 
         $state =  array();  
         $_SESSION['debug'] .= "\nThe input converted to a 4x4 state-array\n";
         for ($i=0; $i<16; $i++)
         {
            //for example the input-byte 5 should go to state[1][1], so state[5%4][floor(5/4)]
            $state[$i%4][floor($i/4)] = $bytearray[$i];  
            //$_SESSION['debug'] .= "state[" . $i%4 . "][" . floor($i/4) . "]=" . $bytearray[$i] . "\n";
         }

         for ($row=0; $row<4; $row++) {
            $_SESSION['debug'] .= "(";
            for ($column=0; $column<4; $column++) {
               $_SESSION['debug'] .= $state[$row][$column];
               if ($column < 3) $_SESSION['debug'] .= ", ";
            }
            $_SESSION['debug'] .= ")\n";
         }
         return $state;
      }

      public function convertStateToByteArray($result)
      {
         for ($i=0; $i<16; $i++)
         {
            //for example state[2][1] should go to output-byte 6, so out[6]=state[6%4][floor(6/4)] 
            $outputarr[$i] = $result[$i%4][floor($i/4)]; 
         }
         $_SESSION['debug'] .= "\nThe result converted back to a linear decimal representation:\n";
         $_SESSION['debug'] .= implode(",", $outputarr);

         for ($i=0; $i<16; $i++)
         {
            $output.= dechex($outputarr[$i])." ";
         }
         return $output;
         }

   }
   
?>