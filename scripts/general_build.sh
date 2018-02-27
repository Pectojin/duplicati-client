#!/bin/bash
# Script for making a general python build
# Requires: zip

# Get version number of code
version=$(awk '/Duplicati client/{getline;print $2}' ../VERSION.md)
dir_name=$(echo "duplicati_client_"$version"_general")

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

cd $dir_name

cp ../../../*.py .

# Add requirements.txt
cp ../../../requirements.txt .

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
