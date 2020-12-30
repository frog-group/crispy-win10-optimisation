rem disable echo
@echo off

rem repo win10script handling
echo "Checking if win10script repository already exists..."
if exist win10script (
	echo "Found!"
	echo "Deleting existing win10script repository..."
	del /f /s /q win10script 1>nul
	rmdir /s /q win10script
	echo "Done!"
) else (
	echo "Not found!"
)
echo "Cloning win10script repository..."
git clone https://github.com/ChrisTitusTech/win10script
echo "Done!"

rem repo windows10-debloat handling
echo "Checking if windows10-debloat repository already exists..."
if exist windows10-debloat (
	echo "Found!"
	echo "Deleting existing windows10-debloat repository..."
	del /f /s /q windows10-debloat 1>nul
	rmdir /s /q windows10-debloat
	echo "Done!"
) else (
	echo "Not found!"
)
echo "Cloning windows10-debloat repository..."
git clone https://github.com/Daksh777/windows10-debloat
echo "Done!"

rem repo Windows10Debloater handling
echo "Checking if Windows10Debloater repository already exists..."
if exist Windows10Debloater (
	echo "Found!"
	echo "Deleting existing Windows10Debloater repository..."
	del /f /s /q Windows10Debloater 1>nul
	rmdir /s /q Windows10Debloater
	echo "Done!"
) else (
	echo "Not found!"
)
echo "Cloning Windows10Debloater repository..."
git clone https://github.com/Sycnex/Windows10Debloater
echo "Done!"
