export $(grep -v '^#' /usr/src/app/.env.prod | xargs -d '\n')

