#!/bin/bash
# Script for building GNU/Linux self contained binary 
# Requires: Pyinstaller, zip

echo "Cleaning up old files..." 
# Cleanup old dist files
if [ -d "dist" ]; then
	rm -rf dist
fi

# Cleanup old build files
if [ -d "build" ]; then
	rm -rf build
fi

pyinstaller=$(which pyinstaller)
echo "Pyinstaller path: " $pyinstaller

echo "Building binary..."
eval "$($pyinstaller -F ../duplicati_client.py --log-level=WARN)"
echo "Pyinstaller exit code: " $?

# Get version number of code
version=$(awk '/Duplicati client/{getline;print $2}' ../VERSION.md)
dir_name=$(echo "duplicati_client_"$version"_gnu_linux")

echo "Build version:" $version
echo "Creating release folder and copying files..."

# Create folder to hold releases if it doesn't exist
if [ ! -d "releases" ]; then
	mkdir releases
fi

cd releases

# Remove release folder if it already exists
rm -rf $dir_name 

# Create release folder
mkdir $dir_name

# Copy binary into release folder
cp ../dist/duplicati_client $dir_name

cd $dir_name
# Add source to release folder
mkdir "source"
cp ../../../*.py source

# Add requirements.txt
cp ../../../requirements.txt source

# Add VERSION.md
cp ../../../VERSION.md .

# Add LICENSE.txt
cp ../../../LICENSE.txt .

# Add README.md
cp ../../../README.md .

cd ..
zip_name=$(echo $dir_name".zip")

# Remove old zip file if it exists
if [ -f $zip_name ]; then
	rm $zip_name
fi

echo "Packing release into a zip archive..."
/usr/bin/zip -r -q $zip_name $dir_name

echo "Done!"
