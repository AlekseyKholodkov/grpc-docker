#!/bin/zsh

url_go_archive="https://go.dev/dl/go1.23.2.darwin-amd64.tar.gz"
download_to_folder="/tmp/go/"
go_folder="/usr/local/"
go_path="$go_folder/go/bin"
# execute to understand which Go version is installed
# which go
# result: /usr/local/go/bin/go

echo "Removing /user/local/go ..."
sudo rm -rf /usr/local/go

if [ ! -d "$download_to_folder" ]; then
    echo "Creating download directory: $download_to_folder"
    mkdir -p "$download_to_folder"
fi

echo "Downloading to: $download_to_folder from: $url_go_archive ..."
curl -oL "$download_to_folder$(basename $url_go_archive)" "$url_go_archive"

if [ $? -eq 0 ]; then
    echo "Download successful"
else
  echo "Download failed!"
  exit 1
fi


echo "Extracting from archive: $download_to_folder$(basename $url_go_archive) to $go_folder"
sudo tar -C "$go_folder" -xzf "$download_to_folder$(basename $url_go_archive)"

if [[ ":$PATH" != *":$go_path"* ]]; then
  echo "Go path not found in PATH. Adding it ..."
  export PATH="$PATH:$go_path"
  echo "export PATH=\$PATH:$go_path" >> ~/.zshrc
  source ~/.zshrc
else
  echo "Go path already present in PATH."
fi

go version
