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

	/**
	 * A do to many function
	 * DV: now also padds with strings.length > 16
	 * @return array|string
	 */
	public function getByteArrayFromInput(){
		$correct = false;
		$retv = "";

		$in = htmlspecialchars(trim($_POST['input']));
		$operation = htmlspecialchars(trim($_POST['operation']));

		if( (!isset($_POST['encmode']))) {
			$_SESSION['debug'] .= "Choose an encryption mode please.";
		}
		else if (isset($_POST['encmode'])) {
			$_SESSION['debug'] .= "Encryption mode: " . $_POST['encmode'] . "\n";
		}

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

                    //todo slopen
				//	$_SESSION['debug'] .= "input to long, maximum length is 16 bytes";


					//read posted data for state data and for data-format (ascii or hex)

					// convert to a decimal representation of the ascii-values, C for unsigned char
					$byteArray = unpack('C*', $in);

					// make bytearray start at index 0, because result from unpack starts at index 1
					$byteArray = array_merge($byteArray);
					self::fillPadding($byteArray);

					$_SESSION['debug'] .= "The input converted to a byte-array with the decimal representation of the ascii-values:";
					$_SESSION['debug'] .= "\n". implode(",", $byteArray) ."\n";
					$retv = $byteArray;
					$correct = true;

			}
			else if ($_POST['format']=='hex'){
				$byteArray = array();
				//removing spaces and 0x hex format specifiers is not fool-proof but gets normal input to just hex numbers
				$in = str_replace(' ', '', $in); //remove all spaces from string
				$in = str_replace('\x', '', $in); // remove all 0x hex format specifiers
				$in = str_replace('0x', '', $in); // remove all 0x hex format specifiers
				$index = 0;
				for ($i=0; $i<strlen($in); $i+=2) {
					$ss = substr($in, $i, 2);
					$byteArray[$index] = hexdec($ss);
					$index++;
				}

				$byteArray = self::fillPadding($byteArray);
				$_SESSION['debug'] .= "The input converted to a byte-array with the decimal representation of the ascii-values:";
				$_SESSION['debug'] .= "\n". implode(",", $byteArray) ."\n";
				$retv = $byteArray;
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

	/**
	 * Fills the padding of $byteArray: adds zero's to the byteArray until the length of bytearray modulo 16 equals 0
	 * @param array $byteArray
	 * @return array $byteArray
	 */
	public function fillPadding($byteArray){
		$ret = array();
		$len = count($byteArray);

		if($len % 16 == 0){
			// padding is ok.
			return $byteArray;
		}else{
			$amount = 16 - ($len % 16);
		}
		for($i = 0 ; $i < $amount ; $i++){
			$ret[$i] = 0;
		}
		echo("padding_byteArray: ");
		var_dump($byteArray);
		echo("<br />");
		echo("padding_ret");
		var_dump($ret);
		echo("<br />");
		return array_merge($byteArray,$ret);
	}

	/**
	 * Converts a bytearray to a single state
	 * @param $byteArray
	 * @return array the state
	 */
	public function getState($byteArray){
		// let's convert the input to the state as done with the AES-input,
		// so first input-byte goes to state[0][0], second input-byte goes to state[1][0], etc
		$state =  array();
		$byteArray = self::fillPadding($byteArray);
		$_SESSION['debug'] .= "\ngetState-methode\n";
		$_SESSION['debug'] .= "\nThe input converted to a 4x4 state-array\n";
		for ($i=0; $i<16; $i++)
		{
			//for example the input-byte 5 should go to state[1][1], so state[5%4][floor(5/4)]
			$state[$i%4][floor($i/4)] = $byteArray[$i];
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

	/**
	 * Convert a byteArray to an array of states.
	 * @param $byteArray
	 * @return array states
	 */
	public function getStates($byteArray){		
		$_SESSION['debug'] .= "\ngetStates(!)-methode\n";	
		$byteArray = self::fillPadding($byteArray);	
		$_SESSION['debug'] .= "bytearray na padding: ".implode(",",$byteArray)."\n";	
		$len = count($byteArray);
		$states = array();
		$counter = 0;
		for($i = 0 ; $i < $len ; $i+=16){
			$states[$counter] = self::getState(array_slice($byteArray,$i,16));
			$_SESSION['debug'] .= "bloknr:".($i/16)."\nstateblok:".implode(",",array_slice($byteArray,$i,16))."\n";			
			$counter++;
		}
		return $states;
	}

	public function convertStateToByteArray($result)
	{
        $outputarr = array();

		for ($i=0; $i<16; $i++)
		{
			//for example state[2][1] should go to output-byte 6, so out[6]=state[6%4][floor(6/4)]
			$outputarr[$i] = $result[$i%4][floor($i/4)];
		}
		$_SESSION['debug'] .= "\nThe result converted back to a linear decimal representation:\n";
		$_SESSION['debug'] .= implode(",", $outputarr);

		/*
		for ($i=0; $i<16; $i++)
		{
			$output.= dechex($outputarr[$i])." ";
		}
		return $output;
		*/
		return $outputarr;
	}
	
		
	public function convertStateToByteString($rage)
	{
        $output = "";

		for ($i=0; $i<16; $i++)
		{
			//for example state[2][1] should go to output-byte 6, so out[6]=state[6%4][floor(6/4)]
			$outputarr[$i] = $rage[$i%4][floor($i/4)];
		}
		$_SESSION['debug'] .= "\nThe result converted back to a linear decimal representation:\n";
		$_SESSION['debug'] .= implode(",", $outputarr);

		for ($i=0; $i<16; $i++)
		{
			  $output.= dechex($outputarr[$i])." ";			
		}
		return $output;
	}

	public function convertStatesToByteString($result)
	{
        $output = "";
		$len = count($result);
		for ($i=0; $i<$len; $i++)
		{
			//for example state[2][1] should go to output-byte 6, so out[6]=state[6%4][floor(6/4)]
			$output .= self::convertStateToByteString($result[$i]);
			 //$output = array_merge($output, self::convertStateToByteArray($result[$i]));
		}
		$_SESSION['debug'] .= "\nconvertStatesToByteString Result: \n";
		$_SESSION['debug'] .= implode(",", $outputarr);
		return $output;
	}

	/**
	* Converts an array of states to a single byte array.
	* @param $input an array of states
	*
	*
	*/
	public function convertStatesToByteArray($result)
	{
		if(!is_array($result)){
			die("No input array! ".$result); // geen idee wat die() voor gevolgen heeft, maar het klinkt effectief.
		}
		$output = array();
		$len = count($result);
		//$_SESSION['debug'] .= "\n".$result[0]."\n";
		//$_SESSION['debug'] .= "\n".implode(", ",$result[0])."\n";
		for ($i=0; $i<$len; $i++)
		{
			//for example state[2][1] should go to output-byte 6, so out[6]=state[6%4][floor(6/4)]
			$output = array_merge($output,self::convertStateToByteArray($result[$i]));
		}
		$_SESSION['debug'] .= "\nThe Result of convertStatesToByteArray: \n";
		$_SESSION['debug'] .= implode(",",$output);
		return $output;
		}

}

?>
