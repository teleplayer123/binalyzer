# start podman
# podman machine init
# podman machine start

# Build the image
# podman build -t linux-security-agent .

# Run the container
podman run -it \
    -u root \
    --network="host" \
    --cap-add=SYS_PTRACE \
    -v $(pwd)/src:/home/analyst \
    linux-security-agent
