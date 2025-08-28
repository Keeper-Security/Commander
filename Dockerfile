FROM python:3.9-slim

ENV PYTHONUNBUFFERED 1

# Create a non-root user for security
RUN groupadd --system --gid 1000 commander && \
    useradd --system --uid 1000 --gid commander --shell /bin/bash --create-home commander

# Set the working directory in the container
WORKDIR /commander

# Copy requirements first for better Docker layer caching
COPY requirements.txt /commander/

# Install the necessary dependencies as root
RUN pip install --no-cache-dir -r requirements.txt

# Copy the local directory contents into the container's directory
COPY . /commander

# Install the package as root
RUN pip install --no-cache-dir -e .

# Change ownership of the application directory to the commander user
RUN chown -R commander:commander /commander

# Switch to non-root user
USER commander

# Set up an entrypoint
ENTRYPOINT ["python3", "keeper.py"]