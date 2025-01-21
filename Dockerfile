FROM amd64/ubuntu:22.04

# Install NASM and Binutils (for ld)
RUN apt-get update && apt-get install -y nasm binutils make vim build-essential bsdmainutils git

# Create a directory to store your assembly file
RUN mkdir FT_NM
# Copy your assembly file into the container
COPY . FT_NM
# Change the working directory
WORKDIR /FT_NM

# Default command: run the resulting program
CMD ["bash"]
