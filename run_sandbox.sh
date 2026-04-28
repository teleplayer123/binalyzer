# start podman
# podman machine init # (only needs to be run once)
# podman machine start

# Build the image
# podman build -t linux-security-agent .

# Run the container
podman run -it \
    -u root \
    --network="host" \
    linux-security-agent
    #-v ./src:/home/analyst