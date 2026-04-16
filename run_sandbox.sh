# start podman
# podman machine init
# podman machine start

# Build the image
# podman build -t linux-security-agent .

# Run the container
podman run -it \
    --network="host" \
    linux-security-agent
    #-v ./src:/home/analyst
    #-u root