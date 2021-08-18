<!DOCTYPE html>
<html>
<body>

<form action="index.php" method="post" enctype="multipart/form-data">
  Select image to upload:
  <input type="file" name="fileToUpload" id="fileToUpload">
  <input type="submit" value="Upload Image" name="submit">
</form>

</body>
</html>

<?php
$target_dir = "/uploads";
$target_file = $target_dir . "/". md5($_SERVER['REMOTE_ADDR'] .random_bytes (16)). ".pdf";
$uploadOk = 1;

if(isset($_POST["submit"])) {
  define('PDF_MAGIC', "\x25\x50\x44\x46\x2D");
  $check = (file_get_contents($_FILES["fileToUpload"]["tmp_name"], false, null, 0, strlen(PDF_MAGIC)) === PDF_MAGIC) ? true : false;
  if($check !== false) {
    echo "File is an pdf \n";
    $uploadOk = 1;
  } else {
    echo "File is not an pdf.\n";
    $uploadOk = 0;
  }
}

// Check if file already exists
if (file_exists($target_file)) {
  echo "Sorry, file already exists.";
  $uploadOk = 0;
}

// Check file size
if ($_FILES["fileToUpload"]["size"] > 500000) {
  echo "Sorry, your file is too large.";
  $uploadOk = 0;
}

if ($uploadOk == 0) {
  echo "Sorry, your file was not uploaded.";
} else {
  if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $target_file)) {
          echo "The file has been uploaded.";
          //echo shell_exec('exiftool '.$target_file);
          echo shell_exec('timeout 10s exiftool '.escapeshellarg($target_file));
          unlink($target_file);
  } else {
    echo "Sorry, there was an error uploading your file. Try again";
  }
}

// code is ugly? Brenocss's fault.

?>
