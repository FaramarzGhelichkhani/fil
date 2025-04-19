#!/bin/sh

bash ./create_multi_user.sh
bash ./user_own_dir.sh

exec "$@"
