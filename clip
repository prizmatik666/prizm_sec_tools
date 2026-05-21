#!/usr/bin/env bash
# this is what i use to transfer data from linux(kali-ssh) to windows clipboard
# chmod +x clip
# put in /usr/local/bin
# usage: cat filename | clip
# when using WSL i had a similiar method setup that i don't have access to anymore
# if this doesn't work for you on wsl, use this concept and ask AI to help make a 
# technique that works on your system. This allows me to quickly send full scripts
# to the clipboard.
base64_data="$(cat | base64 -w 0)"
printf '\033]52;c;%s\007' "$base64_data" > /dev/tty
