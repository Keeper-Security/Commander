FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        openssl \
        ca-certificates && \
    pip install --no-cache-dir --upgrade pip setuptools wheel && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Create a non-root user for security
RUN groupadd --system --gid 1000 commander && \
    useradd --system --uid 1000 --gid commander --shell /bin/bash --create-home commander

# Set the working directory in the container
WORKDIR /commander

# Copy requirements first for better Docker layer caching
COPY requirements.txt /commander/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code and entrypoint
COPY . /commander
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh && \
    mkdir -p /home/commander/.keeper && \
    chown -R commander:commander /commander /home/commander/.keeper && \
    chmod -R 755 /home/commander/.keeper && \
    # Install application with email dependencies
    pip install --no-cache-dir -e .[email]

# Switch to non-root user
USER commander

# Set up an entrypoint
ENTRYPOINT ["docker-entrypoint.sh"]