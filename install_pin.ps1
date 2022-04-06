if ($null -eq $PREFIX) {
    $PREFIX=$HOME
}

$ZIP_NAME="pin-3.20-98437-gf02b61307-msvc-windows"

Invoke-WebRequest -Uri "https://software.intel.com/sites/landingpage/pintool/downloads/${ZIP_NAME}.zip" -UseBasicParsing -OutFile "${ZIP_NAME}.zip"
Expand-Archive -Path "${ZIP_NAME}.zip" -DestinationPath "${PREFIX}" -Force
Remove-Item -Path "${ZIP_NAME}.zip"

Write-Host "Please set:"
Write-Host "`$PIN_ROOT=${PREFIX}\${ZIP_NAME}"