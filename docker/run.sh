# Example of how to user the docker image
POSTGRES_PASSWORD=
docker build . -t headscale-docker
docker run -p 8000:8000 -v $(pwd)/pgdata:/var/lib/postgresql/data -v "$(pwd)/private.key:/build/headscale/private.key" -v "$(pwd)/public.key:/build/headscale/public.key" -e SERVER_URL=127.0.0.1:8000 -e POSTGRES_PASSWORD=$POSTGRES_PASSWORD -ti headscale-docker
