rsync -av --exclude='.env.prod' --exclude='.env.ci' --exclude=' --exclude='fil' --exclude='.git*' --exclude='*.tar' --exclude='ci' --exclude='deploy' --exclude='hub/venv' --exclude='hub/packages' --exclude='log' --exclude='app'  --exclude='hub/users.txt' --exclude='comman_service/log' --exclude='comman_service/kafka' . fil02:/opt/fil-docker/

