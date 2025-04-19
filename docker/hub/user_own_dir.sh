#!/bin/bash
chown -R root:root /home
chmod -R 755 /home

file_path="users.txt"

while IFS=" " read -r name _; do
  chown -R "$name:$name" "/home/$name"
  chmod -R 750 "/home/$name"
done < "$file_path"


